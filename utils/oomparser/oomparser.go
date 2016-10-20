// Copyright 2014 Google Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package oomparser

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/golang/glog"
)

var (
	containerRegexp = regexp.MustCompile(`Task in (.*) killed as a result of limit of (.*)`)
	lastLineRegexp  = regexp.MustCompile(`(^[A-Z][a-z]{2} .*[0-9]{1,2} [0-9]{1,2}:[0-9]{2}:[0-9]{2}) .* Killed process ([0-9]+) \(([\w]+)\)`)
	firstLineRegexp = regexp.MustCompile(`invoked oom-killer:`)
)

// struct to hold file from which we obtain OomInstances
type OomParser struct {
	in io.Reader
}

// struct that contains information related to an OOM kill instance
type OomInstance struct {
	// process id of the killed process
	Pid int
	// the name of the killed process
	ProcessName string
	// the time that the process was reported to be killed,
	// accurate to the minute
	TimeOfDeath time.Time
	// the absolute name of the container that OOMed
	ContainerName string
	// the absolute name of the container that was killed
	// due to the OOM.
	VictimContainerName string
}

// gets the container name from a line and adds it to the oomInstance.
func getContainerName(line string, currentOomInstance *OomInstance) error {
	parsedLine := containerRegexp.FindStringSubmatch(line)
	if parsedLine == nil {
		return nil
	}
	currentOomInstance.ContainerName = path.Join("/", parsedLine[1])
	currentOomInstance.VictimContainerName = path.Join("/", parsedLine[2])
	return nil
}

// gets the pid, name, and date from a line and adds it to oomInstance
func getProcessNamePid(line string, currentOomInstance *OomInstance) (bool, error) {
	reList := lastLineRegexp.FindStringSubmatch(line)

	if reList == nil {
		return false, nil
	}
	const longForm = "Jan _2 15:04:05 2006"
	stringYear := strconv.Itoa(time.Now().Year())
	linetime, err := time.ParseInLocation(longForm, reList[1]+" "+stringYear, time.Local)
	if err != nil {
		return false, err
	}

	currentOomInstance.TimeOfDeath = linetime
	pid, err := strconv.Atoi(reList[2])
	if err != nil {
		return false, err
	}
	currentOomInstance.Pid = pid
	currentOomInstance.ProcessName = reList[3]
	return true, nil
}

// uses regex to see if line is the start of a kernel oom log
func checkIfStartOfOomMessages(line string) bool {
	potential_oom_start := firstLineRegexp.MatchString(line)
	if potential_oom_start {
		return true
	}
	return false
}

// StreamOoms reads `/dev/kmsg` for OOM events and parses out the process that
// was impacted. It returns a stream of events as they occur.
func (self *OomParser) StreamOoms(outStream chan<- *OomInstance) {
	scanner := bufio.NewScanner(self.in)
	for scanner.Scan() {
		line := scanner.Text()
		var continuation bool
		// see https://www.kernel.org/doc/Documentation/ABI/testing/dev-kmsg, strip
		// the syslog stuff by splitting on the first ;
		// Technically not required because the regexes don't anchor on the beginning
		if strings.HasPrefix(line, " ") {
			// Continuation, technically part of the previous line
			continuation = true
		}
		if !continuation {
			lineParts := strings.SplitN(line, ";", 2)
			if len(lineParts) < 2 {
				glog.Warningf("unrecognized kmsg line %q, expected a ';'", line)
				// Continue anyways, could be fine
			} else {
				line = lineParts[1]
			}
		}

		in_oom_kernel_log := checkIfStartOfOomMessages(line)
		if in_oom_kernel_log {
			oomCurrentInstance := &OomInstance{
				ContainerName: "/",
			}
			for scanner.Scan() {
				line := scanner.Text()

				err := getContainerName(line, oomCurrentInstance)
				if err != nil {
					glog.Errorf("%v", err)
				}
				finished, err := getProcessNamePid(line, oomCurrentInstance)
				if err != nil {
					glog.Errorf("%v", err)
				}
				if finished {
					break
				}
			}
			outStream <- oomCurrentInstance
		}
	}
	glog.Warningf("OOMParser exited, OOM events will not be reported.")
}

func newDevKmsgOomParser() (*OomParser, error) {
	kmsg, err := os.Open("/dev/kmsg")
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("'/dev/kmsg' does not exist; unable to parse for OOM events")
		}
		return nil, err
	}

	return &OomParser{
		in: kmsg,
	}, nil
}

// initializes an OomParser object. Returns an OomParser object and an error.
func New() (*OomParser, error) {
	return newDevKmsgOomParser()
}
