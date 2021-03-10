#!/usr/bin/env python
import collections
import mock
import sys
import pytest
import sample_responses


class MockCollectd(mock.MagicMock):
    """
    Mocks the functions and objects provided by the collectd module
    """

    @staticmethod
    def log(log_str):
        print(log_str)

    debug = log
    info = log
    warning = log
    error = log


def mock_api_call(url, api_type, module_config):
    parsed_url = url.split('/')

    print(parsed_url)

    if api_type == 'jenkins' and 'localhost' in parsed_url[-2]:
        return getattr(sample_responses, 'jobs')
    elif api_type == 'jenkins':
        return getattr(sample_responses, "_".join(parsed_url[4:-1]))
    elif api_type == "job_tree":
        return getattr(sample_responses, 'job_tree')
    # one of the endpoints that the plugin needs
    return getattr(sample_responses, api_type)


sys.modules['collectd'] = MockCollectd()

import jenkins

ConfigOption = collections.namedtuple('ConfigOption', ('key', 'values'))

fail_mock_config_required_params = mock.Mock()
fail_mock_config_required_params.children = [
    ConfigOption('Host', ('localhost',)),
    ConfigOption('Port', ('8080',)),
    ConfigOption('Testing', ('True',))
]


def test_config_fail():
    with pytest.raises(ValueError):
        jenkins.read_config(fail_mock_config_required_params)


mock_config_enhanced_metrics_on = mock.Mock()
mock_config_enhanced_metrics_on.children = [
    ConfigOption('Host', ('localhost',)),
    ConfigOption('Port', ('8080',)),
    ConfigOption('MetricsKey', ('6Z95HwGBHOj4uBOlsakGR91dxbFenpfz_g2wdBlUAh0-ocmK-CvdHLSvE1LGRdmg',)),
    ConfigOption('Interval', ('10',)),
    ConfigOption('EnhancedMetrics', ('tRue',)),
    ConfigOption('ExcludeMetric', ('vm.daemon.count',)),
    ConfigOption('Testing', ('True',))
]


mock_config_enhanced_metrics_off = mock.Mock()
mock_config_enhanced_metrics_off.children = [
    ConfigOption('Host', ('localhost',)),
    ConfigOption('Port', ('22379',)),
    ConfigOption('MetricsKey', ('6Z95HwGBHOj4uBOlsakGR91dxbFenpfz_g2wdBlUAh0-ocmK-CvdHLSvE1LGRdmg',)),
    ConfigOption('Interval', ('10',)),
    ConfigOption('IncludeMetric', ('vm.daemon.count',)),
    ConfigOption('Testing', ('True',))
]

mock_read_and_post_job_metrics = mock.Mock()
mock_config_job_metrics_off = mock.Mock()
mock_config_job_metrics_off.children = [
    ConfigOption('Host', ('localhost',)),
    ConfigOption('Port', ('22379',)),
    ConfigOption('MetricsKey', ('6Z95HwGBHOj4uBOlsakGR91dxbFenpfz_g2wdBlUAh0-ocmK-CvdHLSvE1LGRdmg',)),
    ConfigOption('Interval', ('10',)),
    ConfigOption('ExcludeJobMetrics', ('True',)),
    ConfigOption('Testing', ('True',))
]


@mock.patch('jenkins.get_response', mock_api_call)
@mock.patch('jenkins.read_and_post_job_metrics', mock_read_and_post_job_metrics)
def test_job_url():
    module_config = jenkins.read_config(mock_config_enhanced_metrics_off)
    jenkins.read_metrics(module_config)
    args = mock_read_and_post_job_metrics.call_args.args
    assert args[1].startswith(module_config["base_url"])


@mock.patch('jenkins.get_response', mock_api_call)
@mock.patch('jenkins.read_and_post_job_metrics', mock_read_and_post_job_metrics)
def test_job_metrics_off():
    mock_read_and_post_job_metrics.reset_mock()
    module_config = jenkins.read_config(mock_config_job_metrics_off)
    jenkins.read_metrics(module_config)
    mock_read_and_post_job_metrics.assert_not_called()


@mock.patch('jenkins.get_response', mock_api_call)
def test_optional_metrics_on():
    jenkins.read_metrics(
        jenkins.read_config(
            mock_config_enhanced_metrics_off))


@mock.patch('jenkins.get_response', mock_api_call)
def test_optional_metrics_off():
    jenkins.read_metrics(
        jenkins.read_config(
            mock_config_enhanced_metrics_on))


mock_config = mock.Mock()
mock_config.children = [
    ConfigOption('Host', ('localhost',)),
    ConfigOption('Port', ('2379',)),
    ConfigOption('MetricsKey', ('6Z95HwGBHOj4uBOlsakGR91dxbFenpfz_g2wdBlUAh0-ocmK-CvdHLSvE1LGRdmg',)),
    ConfigOption('Interval', ('60',)),
    ConfigOption('Testing', ('True',))
]


def test_default_config():
    module_config = jenkins.read_config(mock_config)
    assert module_config['plugin_config']['Host'] == 'localhost'
    assert module_config['plugin_config']['Port'] == '2379'
    assert module_config['metrics_key'] == '6Z95HwGBHOj4uBOlsakGR91dxbFenpfz_g2wdBlUAh0-ocmK-CvdHLSvE1LGRdmg'
    assert module_config['base_url'] == 'http://localhost:2379/'


mock_config_check_bool = mock.Mock()
mock_config_check_bool.children = [
    ConfigOption('Host', ('localhost',)),
    ConfigOption('Port', ('2379',)),
    ConfigOption('MetricsKey', ('6Z95HwGBHOj4uBOlsakGR91dxbFenpfz_g2wdBlUAh0-ocmK-CvdHLSvE1LGRdmg',)),
    ConfigOption('Interval', ('10',)),
    ConfigOption('EnhancedMetrics', ('xyz',)),
    ConfigOption('Testing', ('True',))
]


def test_boolean_config():
    module_config = jenkins.read_config(mock_config_check_bool)
    assert module_config['plugin_config']['Host'] == 'localhost'
    assert module_config['plugin_config']['Port'] == '2379'
    assert module_config['metrics_key'] == '6Z95HwGBHOj4uBOlsakGR91dxbFenpfz_g2wdBlUAh0-ocmK-CvdHLSvE1LGRdmg'
    assert module_config['base_url'] == 'http://localhost:2379/'
    assert module_config['enhanced_metrics'] == False
    assert module_config['exclude_job_metrics'] == False


@mock.patch('jenkins.get_response', mock_api_call)
def test_read():
    jenkins.read_metrics(jenkins.read_config(mock_config))


def test_get_auth_args():
    module_config = jenkins.read_config(mock_config)
    auth_args = jenkins.get_auth_args(module_config)
    assert 'auth' not in auth_args
