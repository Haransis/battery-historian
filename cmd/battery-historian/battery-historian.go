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

// Historian v2 analyzes bugreports and outputs battery analysis results.
package main

import (
	"flag"
	"fmt"
	"io/ioutil"

	"github.com/google/battery-historian/analyzer"
)

var (
	inputFile  = flag.String("input_file", "", "bugreport (zip) to analyze")
	outputPath = flag.String("output_dir", "", "path for output csv")
	process    = flag.String("process", "", "Process to monitor")
	duration   = flag.Int("duration", 1, "Duration of the experiment (min) > 1")

	compiledDir   = flag.String("compiled_dir", "./compiled", "Directory containing compiled js file for Historian v2.")
	scriptsDir    = flag.String("scripts_dir", "./scripts", "Directory containing Historian and kernel trace Python scripts.")
	thirdPartyDir = flag.String("third_party_dir", "./third_party", "Directory containing third party files for Historian v2.")

	// resVersion should be incremented whenever the JS or CSS files are modified.
	resVersion = flag.Int("res_version", 2, "The current version of JS and CSS files. Used to force JS and CSS reloading to avoid cache issues when rolling out new versions.")
)

func compiledPath() string {
	dir := *compiledDir
	if dir == "" {
		dir = "./compiled"
	}
	return dir
}

func thirdPartyPath() string {
	dir := *thirdPartyDir
	if dir == "" {
		dir = "./third_party"
	}
	return dir
}

func main() {
	flag.Parse()

	analyzer.SetScriptsDir(*scriptsDir)
	analyzer.SetResVersion(*resVersion)
	data, err := ioutil.ReadFile(*inputFile)
	if err != nil {
		fmt.Println("File reading error", err)
		return
	}
	analyzer.ParseBugReport(*inputFile, string(data), *outputPath, *process, *duration)
}
