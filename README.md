> # :warning: End of Support (EoS) Notice
> 
> This plugin is deprecated and no longer maintained.

>ℹ️&nbsp;&nbsp;SignalFx was acquired by Splunk in October 2019. See [Splunk SignalFx](https://www.splunk.com/en_us/investor-relations/acquisitions/signalfx.html) for more information.

# collectd jenkins Plugin

A Jenkins collectd plugin which users can use to send metrics from Jenkins instances to SignalFx.

## Installation

* Checkout this repository somewhere on your system accessible by collectd. The suggested location is `/usr/share/collectd/`
* Install the Python requirements with `sudo pip install -r requirements.txt`
* Install the Metrics Plugin in Jenkins. `Manage Jenkins > Manage Plugins > Available > Search "Metrics Plugin"`
* Configure the plugin (see below)
* Restart collectd

## Requirements

* collectd 4.9 or later (for the Python plugin)
* Python 2.7 or later
* Jenkins 1.580.3 or later
* `Metrics Plugin`(see installation steps)

## Configuration

The following are required configuration keys:

* Host - Required. Hostname or IP address of the etcd member, default is 'localhost'
* Port - Required. The port of the jenkins instance, default is '8080'
* MetricsKey - Required. The access key from `Manage Jenkins > Configure System > Metrics > ADD`. If empty, click Generate

Optional configurations keys include:

* Interval - Interval between metric calls. Default is 10s
* Username - user id with access, if any. Username will require APIToken too
* APIToken - API token from the system configuration in Jenkins. `Username > Configure > API Token > Show API Token`
* Path - URL prefix to use in the HTTP request
* EnhancedMetrics - Flag to specify whether advanced stats from the `/metrics/<MetricsKey>/metrics` endpoint are needed. Default is False
* IncludeMetric - Advanced Metrics from the `/metrics/<MetricsKey>/metrics` endpoint can be included individually
* ExcludeMetric - Advanced Metrics from the `/metrics/<MetricsKey>/metrics` endpoint can be excluded individually
* Dimension - Add extra dimensions to your metrics
* ExcludeJobMetrics - Flag to specify whether to exclude calls to `/json/api` for all jobs and builds.

### SSL/TLS

* ssl_enabled - True to perform HTTP requests over TLS. Default is False
* ssl_cert_validation - False to skip certificate validation. Default is True

To enable client certificate authentication specify these options:

* ssl_keyfile - path to file
* ssl_certificate - path to file

Provide a custom file that lists trusted CA certificates, required when keyfile and certificate are provided or the server certificate is not signed by a system CA:

* ssl_ca_certs - path to file

From `/metrics/<MetricsKey>/metrics` only the metrics inside `gauges` key are representable, if the value is a number. Metrics of type `histograms`, `meter` and `timer` will be skipped over. Check out `https://wiki.jenkins.io/display/JENKINS/Metrics+Plugin` for description of the metrics.

Note that multiple Jenkins instances can be configured in the same file.

```
LoadPlugin python
<Plugin python>
    ModulePath "/usr/share/collectd/collectd-jenkins"
    Import jenkins
    <Module jenkins>
        Host "localhost"
        Port "8080"
        Username "john"
        APIToken "f04fff7c860d884f2ef00a2b2d481c2f"
        MetricsKey "6ZHwGBkGR91dxbFenpfz_g2h0-ocmK-CvdHLdmg"
        Interval 10
    </Module>
    <Module jenkins>
        Host "localhost"
        Port "8010"
        Username "admin"
        APIToken "f04bbb7c860d8b4f1ef00a2b2d481c2f"
        MetricsKey "6Z76HwGBHOj4uBOlsxbFenpfz_g2UAh0-ocmK-CvdHLSRdmg"
        EnhancedMetrics False
        IncludeMetric "vm.daemon.count"
        IncludeMetric "vm.terminated.count"
    </Module>
    <Module jenkins>
        Host "localhost"
        Port "8000"
        MetricsKey "6Z95HwOj4uBOakGR91dxbFenpfz_g2wBlUAh0-ocmK-CvdSvE1LGRdmg"
        EnhancedMetrics True
        ExcludeMetric "vm.terminated.count"
        ExcludeMetric "vm.daemon.count"
        Dimension foo bar
    </Module>
</Plugin>
```
