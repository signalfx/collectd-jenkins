import time

job_tree = {
  "_class": "hudson.model.Hudson",
  "jobs": [
    {
      "_class": "com.cloudbees.hudson.plugins.folder.Folder",
      "name": "emptyfolder",
      "url": "http://localhost:8003/job/emptyfolder/",
      "jobs": [

      ]
    },
    {
      "_class": "com.cloudbees.hudson.plugins.folder.Folder",
      "name": "testfolder",
      "url": "http://localhost:8003/job/testfolder/",
      "jobs": [
        {
          "_class": "com.cloudbees.hudson.plugins.folder.Folder",
          "name": "nestedfilder",
          "url": "http://localhost:8003/job/testfolder/job/nestedfolder/",
          "jobs": [
            {
              "_class": "hudson.model.FreeStyleProject",
              "name": "nestedfolderjob",
              "url": "http://localhost:8003/job/testfolder/job/nestedfolder/job/nestedfolderjob/"
            }
          ]
        },
        {
          "_class": "hudson.model.FreeStyleProject",
          "name": "testfolderjob",
          "url": "http://localhost:8003/job/testfolder/job/testfolderjob/"
        }
      ]
    },
    {
      "_class": "hudson.model.FreeStyleProject",
      "name": "Data1",
      "url": "http://localhost:8080/job/testjob/",
      "color": "blue"
    }
  ]
}

testjob = {
  "builds": [
    {
      "_class": "hudson.model.FreeStyleBuild",
      "number": 18,
      "url": "http://localhost:8080/job/Test/Build2/"
    },
    {
      "_class": "hudson.model.FreeStyleBuild",
      "number": 17,
      "url": "http://localhost:8080/job/Test/Build1/"
    }
  ]
}

testjob_17 = {
  "building": "false",
  "duration": 515,
  "result": "SUCCESS",
  "timestamp": int(time.time() * 1000),

}

testjob_18 = {
  "building": "true",
  "duration": 515,
  "result": "",
  "timestamp": int(time.time() * 1000),

}

testfolder_job_testfolderjob = {
  "builds": [
    {
      "_class": "hudson.model.FreeStyleProject",
      "number": 20,
      "url": "http://localhost:8003/job/testfolder/job/testfolderjob/Build1/"
    },
  ]
}

testfolder_job_testfolderjob_20 = {
  "building": "true",
  "duration": 515,
  "result": "",
  "timestamp": int(time.time() * 1000),
}

testfolder_job_nestedfolder_job_nestedfolderjob = {
  "builds": [
    {
      "_class": "hudson.model.FreeStyleProject",
      "number": 21,
      "url": "http://localhost:8003/job/testfolder/job/nestedfolder/job/nestedfolderjob/Build2/"
    },
  ]
}

testfolder_job_nestedfolder_job_nestedfolderjob_21 = {
  "building": "true",
  "duration": 515,
  "result": "",
  "timestamp": int(time.time() * 1000),
}

metrics = {
	"gauges": {
		"jenkins.executor.count.value": {
			"value": 2
		},
		"jenkins.executor.free.value": {
			"value": 1
		},
		"jenkins.executor.in-use.value": {
			"value": 1
		},
		"jenkins.health-check.count": {
			"value": 4
		},
		"jenkins.health-check.inverse-score": {
			"value": 0
		},
		"jenkins.health-check.score": {
			"value": 1
		},
		"jenkins.job.count.value": {
			"value": 9
		},
		"jenkins.node.count.value": {
			"value": 3
		},
		"jenkins.node.offline.value": {
			"value": 2
		},
		"jenkins.node.online.value": {
			"value": 1
		},
		"jenkins.queue.blocked.value": {
			"value": 0
		},
		"jenkins.queue.buildable.value": {
			"value": 0
		},
		"jenkins.queue.pending.value": {
			"value": 0
		},
		"jenkins.queue.size.value": {
			"value": 0
		},
		"jenkins.queue.stuck.value": {
			"value": 0
		},
		"system.cpu.load": {
			"value": 1.37548828125
		},
		"vm.blocked.count": {
			"value": 0
		},
		"vm.count": {
			"value": 37
		},
		"vm.cpu.load": {
			"value": 0.019298992479069108
		},
		"vm.daemon.count": {
			"value": 30
		},
		"vm.deadlock.count": {
			"value": 0
		},
		"vm.deadlocks": {
			"value": [ ]
		},
		"vm.file.descriptor.ratio": {
			"value": 0.02626953125
		},
		"vm.memory.heap.usage": {
			"value": 0.3963186220070664
		},
		"vm.memory.non-heap.usage": {
			"value": -110174344
		},
		"vm.memory.total.used": {
			"value": 299616040
		},
		"vm.new.count": {
			"value": 0
		},
		"vm.runnable.count": {
			"value": 13
		},
		"vm.terminated.count": {
			"value": 0
		},
		"vm.timed_waiting.count": {
			"value": 10
		},
		"vm.uptime.milliseconds": {
			"value": 12179131
		},
		"vm.waiting.count": {
			"value": 14
		}
	},
	"counters": {
        "http.activeRequests": {
            "count": 1
        },
        "jenkins_bfa.category.build-failure": {
            "count": 8
        }
    }
}

healthcheck = {
	"disk-space": {
		"healthy": "true"
	},
	"plugins": {
		"healthy": "true",
		"message": "No failed plugins"
	},
	"temporary-space": {
		"healthy": "true"
	},
	"thread-deadlock": {
		"healthy": "true"
	}
}

computer = {
	"computer" :[
					{
						"_class": "hudson.model.Hudson$MasterComputer",
						"displayName": "master",
						"offline": "false",
					},
					{
						"_class": "hudson.slaves.SlaveComputer",
						"displayName": "Slave 2",
						"offline": "true",
					}
				]
}

ping = True
