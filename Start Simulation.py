"""
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta

def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'run_script_1' block
    run_script_1(container=container)

    return

def run_script_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('run_script_1() called')

    # collect data for 'run_script_1' call

    parameters = []
    
    # build parameters list for 'run_script_1' call
    parameters.append({
        'ip_hostname': "172.31.76.156",
        'script_file': "",
        'script_str': "eventcreate /id 999 /D \"started\" /T INFORMATION /L application",
        'parser': "",
        'async': "",
        'command_id': "",
        'shell_id': "",
    })

    phantom.act("run script", parameters=parameters, app={ "name": 'Windows Remote Management' }, name="run_script_1")

    return

def on_finish(container, summary):
    phantom.debug('on_finish() called')
    # This function is called after all actions are completed.
    # summary of all the action and/or all detals of actions 
    # can be collected here.

    # summary_json = phantom.get_summary()
    # if 'result' in summary_json:
        # for action_result in summary_json['result']:
            # if 'action_run_id' in action_result:
                # action_results = phantom.get_action_results(action_run_id=action_result['action_run_id'], result_data=False, flatten=False)
                # phantom.debug(action_results)

    return