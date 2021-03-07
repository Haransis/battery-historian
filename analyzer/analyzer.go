// Copyright 2016 Google Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package analyzer analyzes the uploaded bugreport and displays the results to the user.
package analyzer

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"os"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/golang/protobuf/proto"

	"github.com/google/battery-historian/activity"
	"github.com/google/battery-historian/broadcasts"
	"github.com/google/battery-historian/bugreportutils"
	"github.com/google/battery-historian/checkinparse"
	"github.com/google/battery-historian/checkinutil"
	"github.com/google/battery-historian/dmesg"
	"github.com/google/battery-historian/historianutils"
	"github.com/google/battery-historian/packageutils"
	"github.com/google/battery-historian/parseutils"
	"github.com/google/battery-historian/presenter"
	"github.com/google/battery-historian/wearable"

	bspb "github.com/google/battery-historian/pb/batterystats_proto"
	sessionpb "github.com/google/battery-historian/pb/session_proto"
	usagepb "github.com/google/battery-historian/pb/usagestats_proto"
)

const (
	// maxFileSize is the maximum file size allowed for uploaded package.
	maxFileSize = 100 * 1024 * 1024 // 100 MB Limit

	minSupportedSDK        = 21 // We only support Lollipop bug reports and above
	numberOfFilesToCompare = 2

	// Historian V2 Log sources
	batteryHistory  = "Battery History"
	broadcastsLog   = "Broadcasts"
	eventLog        = "Event"
	kernelDmesg     = "Kernel Dmesg"
	kernelTrace     = "Kernel Trace"
	lastLogcat      = "Last Logcat"
	locationLog     = "Location"
	powerMonitorLog = "Power Monitor"
	systemLog       = "System"
	wearableLog     = "Wearable"

	// Analyzable file types.
	bugreportFT    = "bugreport"
	bugreport2FT   = "bugreport2"
	kernelFT       = "kernel"
	powerMonitorFT = "powermonitor"
)

var (
	// Initialized in InitTemplates()
	uploadTempl  *template.Template
	resultTempl  *template.Template
	compareTempl *template.Template

	// Initialized in SetScriptsDir()
	scriptsDir    string
	isOptimizedJs bool

	// Initialized in SetResVersion()
	resVersion int

	// batteryRE is a regular expression that matches the time information for battery.
	// e.g. 9,0,l,bt,0,86546081,70845214,99083316,83382448,1458155459650,83944766,68243903
	batteryRE = regexp.MustCompile(`9,0,l,bt,(?P<batteryTime>.*)`)
)

type historianData struct {
	html string
	err  error
}

type csvData struct {
	csv  string
	errs []error
}

type historianV2Log struct {
	// Log source that the CSV is generated from.
	// e.g. "batteryhistory" or "eventlog".
	Source string `json:"source"`
	CSV    string `json:"csv"`
	// Optional start time of the log as unix time in milliseconds.
	StartMs int64 `json:"startMs"`
}

type uploadResponse struct {
	SDKVersion          int                      `json:"sdkVersion"`
	HistorianV2Logs     []historianV2Log         `json:"historianV2Logs"`
	LevelSummaryCSV     string                   `json:"levelSummaryCsv"`
	DisplayPowerMonitor bool                     `json:"displayPowerMonitor"`
	ReportVersion       int32                    `json:"reportVersion"`
	AppStats            []presenter.AppStat      `json:"appStats"`
	BatteryStats        *bspb.BatteryStats       `json:"batteryStats"`
	DeviceCapacity      float32                  `json:"deviceCapacity"`
	HistogramStats      presenter.HistogramStats `json:"histogramStats"`
	TimeToDelta         map[string]string        `json:"timeToDelta"`
	CriticalError       string                   `json:"criticalError"` // Critical errors are ones that cause parsing of important data to abort early and should be shown prominently to the user.
	Note                string                   `json:"note"`          // A message to show to the user that they should be aware of.
	FileName            string                   `json:"fileName"`
	Location            string                   `json:"location"`
	OverflowMs          int64                    `json:"overflowMs"`
	IsDiff              bool                     `json:"isDiff"`
}

type summariesData struct {
	summaries       []parseutils.ActivitySummary
	historianV2CSV  string
	levelSummaryCSV string
	timeToDelta     map[string]string
	errs            []error
	overflowMs      int64
}

type checkinData struct {
	batterystats *bspb.BatteryStats
	warnings     []string
	err          []error
}

// BatteryStatsInfo holds the extracted batterystats details for a bugreport.
type BatteryStatsInfo struct {
	Filename string
	Stats    *bspb.BatteryStats
	Meta     *bugreportutils.MetaInfo
}

// scriptsPath expands the script filename into a full resource path for the script.
func scriptsPath(dir, script string) string {
	if len(dir) == 0 {
		dir = "./scripts"
	}
	return path.Join(dir, script)
}

// SetScriptsDir sets the directory of the Historian and kernel trace Python scripts.
func SetScriptsDir(dir string) {
	scriptsDir = dir
}

// SetResVersion sets the current version to force reloading of JS and CSS files.
func SetResVersion(v int) {
	resVersion = v
}

// writeTempFile writes the contents to a temporary file.
func writeTempFile(contents string) (string, error) {
	tmpFile, err := ioutil.TempFile("", "historian")
	if err != nil {
		return "", err
	}
	tmpFile.WriteString(contents)
	if err := tmpFile.Close(); err != nil {
		os.Remove(tmpFile.Name())
		return "", err
	}
	return tmpFile.Name(), nil
}

// ParseBugReport analyzes the given bug report contents, and updates the ParsedData object.
// contentsB is an optional second bug report. If it's given and the Android IDs and batterystats
// checkin start times are the same, a diff of the checkins will be saved, otherwise, they will be
// saved as separate reports.
func ParseBugReport(fnameA, contentsA, outputPath, processName string) error {

	doActivity := func(ch chan activity.LogsData, contents string, pkgs []*usagepb.PackageInfo) {
		ch <- activity.Parse(pkgs, contents)
	}

	doBroadcasts := func(ch chan csvData, contents string) {
		csv, errs := broadcasts.Parse(contents)
		ch <- csvData{csv: csv, errs: errs}
	}

	doCheckin := func(ch chan checkinData, meta *bugreportutils.MetaInfo, bs string, pkgs []*usagepb.PackageInfo) {
		var ctr checkinutil.IntCounter
		s := &sessionpb.Checkin{
			Checkin:          proto.String(bs),
			BuildFingerprint: proto.String(meta.BuildFingerprint),
		}
		stats, warnings, errs := checkinparse.ParseBatteryStats(&ctr, checkinparse.CreateBatteryReport(s), pkgs)
		if stats == nil {
			errs = append(errs, errors.New("could not parse aggregated battery stats"))
		}
		ch <- checkinData{stats, warnings, errs}
		log.Printf("Trace finished processing checkin.")
	}

	doDmesg := func(ch chan dmesg.Data, contents string) {
		ch <- dmesg.Parse(contents)
	}

	// bs is the batterystats section of the bug report
	doSummaries := func(ch chan summariesData, bs string, pkgs []*usagepb.PackageInfo) {
		ch <- analyze(bs, pkgs)
		log.Printf("Trace finished processing summary data.")
	}

	doWearable := func(ch chan string, loc, contents string) {
		if valid, output, _ := wearable.Parse(contents, loc); valid {
			ch <- output
		} else {
			ch <- ""
		}
	}

	type brData struct {
		fileName string
		contents string
		meta     *bugreportutils.MetaInfo
		bt       *bspb.BatteryStats_System_Battery
		dt       time.Time
	}

	// doParsing needs to be declared before its initialization so that it can call itself recursively.
	var doParsing func(brDA *brData)
	// The earlier report will be subtracted from the later report.
	doParsing = func(brDA *brData) {
		if brDA == nil {
			return
		}
		if brDA.fileName == "" || brDA.contents == "" {
			return
		}

		diff := false
		var earl, late *brData

		late = brDA
		log.Printf("Trace started analyzing %q file.", brDA.fileName)

		// Generate the Historian plot and Volta parsing simultaneously.
		summariesCh := make(chan summariesData)
		activityManagerCh := make(chan activity.LogsData)
		broadcastsCh := make(chan csvData)
		dmesgCh := make(chan dmesg.Data)
		wearableCh := make(chan string)
		var checkinL, checkinE checkinData
		var warnings []string
		var bsStats *bspb.BatteryStats
		var errs []error
		supV := late.meta.SdkVersion >= minSupportedSDK && (!diff || earl.meta.SdkVersion >= minSupportedSDK)

		if !supV {
			errs = append(errs, errors.New("unsupported bug report version"))
		} else {
			// No point running these if we don't support the sdk version since we won't get any data from them.

			bsL := bugreportutils.ExtractBatterystatsCheckin(late.contents)
			if strings.Contains(bsL, "Exception occurred while dumping") {
				errs = append(errs, errors.New("exception found in battery dump"))
			}

			pkgsL, pkgErrs := packageutils.ExtractAppsFromBugReport(late.contents)
			errs = append(errs, pkgErrs...)
			checkinLCh := make(chan checkinData)
			go doCheckin(checkinLCh, late.meta, bsL, pkgsL)
			// These are only parsed for supported sdk versions, even though they are still
			// present in unsupported sdk version reports, because the events are rendered
			// with Historian v2, which is not generated for unsupported sdk versions.
			go doActivity(activityManagerCh, late.contents, pkgsL)
			go doBroadcasts(broadcastsCh, late.contents)
			go doDmesg(dmesgCh, late.contents)
			go doWearable(wearableCh, late.dt.Location().String(), late.contents)
			go doSummaries(summariesCh, bsL, pkgsL)

			checkinL = <-checkinLCh
			errs = append(errs, checkinL.err...)
			warnings = append(warnings, checkinL.warnings...)
			if checkinL.batterystats == nil || (checkinE.batterystats == nil) {
				errs = append(errs, errors.New("could not parse aggregated battery stats"))
			} else {
				bsStats = checkinL.batterystats
			}
		}

		var summariesOutput summariesData
		var activityManagerOutput activity.LogsData
		var broadcastsOutput csvData
		var dmesgOutput dmesg.Data
		var wearableOutput string

		if supV {
			summariesOutput = <-summariesCh
			activityManagerOutput = <-activityManagerCh
			broadcastsOutput = <-broadcastsCh
			dmesgOutput = <-dmesgCh
			wearableOutput = <-wearableCh
			errs = append(errs, append(broadcastsOutput.errs, append(dmesgOutput.Errs, append(summariesOutput.errs, activityManagerOutput.Errs...)...)...)...)
		}

		warnings = append(warnings, activityManagerOutput.Warnings...)
		fn := late.fileName
		data := presenter.Data(late.meta, fn,
			summariesOutput.summaries,
			bsStats, "historianOutput.html",
			warnings,
			errs, summariesOutput.overflowMs > 0, true)

		historianV2Logs := []historianV2Log{
			{
				Source: batteryHistory,
				CSV:    summariesOutput.historianV2CSV,
			},
			{
				Source: wearableLog,
				CSV:    wearableOutput,
			},
			{
				Source:  kernelDmesg,
				CSV:     dmesgOutput.CSV,
				StartMs: dmesgOutput.StartMs,
			},
			{
				Source: broadcastsLog,
				CSV:    broadcastsOutput.csv,
			},
		}

		fileSys, err := os.Create(outputPath + "power_report.csv")
		if err != nil {
			fmt.Println(err)
			fileSys.Close()
			return
		}

		scanner := bufio.NewScanner(strings.NewReader(summariesOutput.historianV2CSV))
		line := ""
		for scanner.Scan() {
			line = scanner.Text()
			if strings.Contains(line, "Coulomb charge") || strings.Contains(line, "Voltage") {
				fmt.Fprintln(fileSys, line)
				if err != nil {
					fmt.Println(err)
					return
				}
			}
		}
		err = fileSys.Close()
		if err != nil {
			fmt.Println(err)
			return
		}
		fmt.Println("DeviceFile written successfully")

		for s, l := range activityManagerOutput.Logs {
			if l == nil {
				log.Print("Nil logcat log received")
				continue
			}
			source := ""
			switch s {
			case activity.EventLogSection:
				source = eventLog
			case activity.SystemLogSection:
				source = systemLog
			case activity.LastLogcatSection:
				source = lastLogcat
			default:
				log.Printf("Logcat section %q not handled", s)
				// Show it anyway.
				source = s
			}
			historianV2Logs = append(historianV2Logs, historianV2Log{
				Source:  source,
				CSV:     l.CSV,
				StartMs: l.StartMs,
			})
		}

		fileApp, err := os.Create(outputPath + "summary.csv")
		if err != nil {
			fmt.Println(err)
			fileApp.Close()
			return
		}

		fmt.Fprintln(fileApp, "Estimated Battery Capacity (mAh),", bsStats.GetSystem().GetBattery().GetEstimatedBatteryCapacityMah())
		fmt.Fprintln(fileApp, "PowerUse Declared Battery Capacity (mAh),", bsStats.GetSystem().GetPowerUseSummary().GetBatteryCapacityMah())
		fmt.Fprintln(fileApp, "Device Battery Discharge (mAh),", bsStats.GetSystem().GetBatteryDischarge().GetTotalMah())             //If you follow the history
		fmt.Fprintln(fileApp, "Device Battery Discharge lower bound (%),", bsStats.GetSystem().GetBatteryDischarge().GetLowerBound()) //Compared to declared capacity using below
		fmt.Fprintln(fileApp, "Device Battery Discharge upper bound (%),", bsStats.GetSystem().GetBatteryDischarge().GetUpperBound()) //Compared to declared capacity using below
		fmt.Fprintln(fileApp, "PowerUse lower bound (mAh),", bsStats.GetSystem().GetPowerUseSummary().GetMinDrainedPowerMah())        //"actual"
		fmt.Fprintln(fileApp, "PowerUse upper bound (mAh),", bsStats.GetSystem().GetPowerUseSummary().GetMaxDrainedPowerMah())        //"actual"
		fmt.Fprintln(fileApp, "PowerUse Battery Consumption (mAh),", bsStats.GetSystem().GetPowerUseSummary().GetComputedPowerMah())  //Crazy high value
		fmt.Fprintln(fileApp, "System poweruse item (all sources of consumption),", bsStats.GetSystem().GetPowerUseItem())            //Crazy high values

		for _, appStat := range data.AppStats {
			if *appStat.RawStats.Name == processName {
				fmt.Fprintln(fileApp, "App cpu power estimation (mAh),", (appStat.RawStats.GetCpu().GetPowerMaMs() / (1000 * 60 * 60))) // DevicePowerPrediction and CPUPowerPrediction
				fmt.Fprintln(fileApp, "App total power estimation (mAh),", appStat.RawStats.GetPowerUseItem().GetComputedPowerMah())
				fmt.Fprintln(fileApp, "App cpu power estimation (%),", appStat.CPUPowerPrediction)
				fmt.Fprintln(fileApp, "App total power estimation (%),", appStat.DevicePowerPrediction)
				if err != nil {
					fmt.Println(err)
					return
				}
				break
			}
		}
		err = fileApp.Close()
		if err != nil {
			fmt.Println(err)
			return
		}
		fmt.Println("AppFile written successfully")
		return

	}

	newBrData := func(fName, contents string) (*brData, error) {
		if fName == "" || contents == "" {
			return nil, nil
		}
		br := brData{fileName: fName, contents: contents}
		var err error
		br.meta, err = bugreportutils.ParseMetaInfo(contents)
		if err != nil {
			// If there are issues getting the meta info, then the file is most likely not a bug report.
			return nil, errors.New("error parsing the bug report. Please provide a well formed bug report")
		}
		var errs []error
		br.bt, errs = batteryTime(contents)
		if len(errs) > 0 {
			log.Printf("failed to extract battery info: %s", historianutils.ErrorsToString(errs))
			// It's fine to continue if this fails.
		}
		br.dt, err = bugreportutils.DumpState(contents)
		if err != nil {
			log.Printf("failed to extract time information from bugreport dumpstate: %v", err)
		}
		return &br, nil
	}

	brA, err := newBrData(fnameA, contentsA)
	if err != nil {
		return err
	}
	doParsing(brA)

	return nil
}

func analyze(bugReport string, pkgs []*usagepb.PackageInfo) summariesData {
	upm, errs := parseutils.UIDAndPackageNameMapping(bugReport, pkgs)

	var bufTotal, bufLevel bytes.Buffer
	// repTotal contains summaries over discharge intervals
	repTotal := parseutils.AnalyzeHistory(&bufTotal, bugReport, parseutils.FormatTotalTime, upm, false)
	// repLevel contains summaries for each battery level drop.
	// The generated errors would be the exact same as repTotal.Errs so no need to track or add them again.
	parseutils.AnalyzeHistory(&bufLevel, bugReport, parseutils.FormatBatteryLevel, upm, false)

	// Exclude summaries with no change in battery level
	var summariesTotal []parseutils.ActivitySummary
	for _, s := range repTotal.Summaries {
		if s.InitialBatteryLevel != s.FinalBatteryLevel {
			summariesTotal = append(summariesTotal, s)
		}
	}

	errs = append(errs, repTotal.Errs...)
	return summariesData{summariesTotal, bufTotal.String(), bufLevel.String(), repTotal.TimeToDelta, errs, repTotal.OverflowMs}
}

// batteryTime extracts the battery time info from a bug report.
func batteryTime(contents string) (*bspb.BatteryStats_System_Battery, []error) {
	for _, line := range strings.Split(contents, "\n") {
		if m, result := historianutils.SubexpNames(batteryRE, line); m {
			s := &bspb.BatteryStats_System{}
			record := strings.Split(result["batteryTime"], ",")
			_, errs := checkinparse.SystemBattery(&checkinutil.PrefixCounter{}, record, s)
			if len(errs) > 0 {
				return nil, errs
			}
			return s.GetBattery(), nil
		}
	}
	return nil, []error{errors.New("could not find battery time info in bugreport")}
}
