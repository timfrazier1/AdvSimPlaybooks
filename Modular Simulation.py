"""
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta

def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'Format_Start_Event' block
    Format_Start_Event(container=container)

    return

def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('decision_1() called')

    # check for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["Format_ART_Command:action_result.data.*.executor.name", "==", "powershell"],
            ["Format_ART_Command:action_result.data.*.executor.name", "==", "command_prompt"],
        ],
        logical_operator='or')

    # call connected blocks if condition 1 matched
    if matched_artifacts_1 or matched_results_1:
        filter_1(action=action, success=success, container=container, results=results, handle=handle)
        return

    # call connected blocks for 'else' condition 2
    Run_User_Supplied_Cmd(action=action, success=success, container=container, results=results, handle=handle)

    return

def Format_ART_Command(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('format_command_1() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'format_command_1' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.os', 'artifact:*.cef.act', 'artifact:*.cef.input_arguments', 'artifact:*.id'])

    parameters = []
    # build parameters list for 'format_command_1' call
    for container_item in container_data:
        if container_item[0] and container_item[1]:
            phantom.debug(container_item[1])

            parameters.append({
                'supported_os': container_item[0],
                'attack_id': container_item[1],
                'input_arguments': container_item[2],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[3]},
            })

    phantom.act("format command", parameters=parameters, app={ "name": 'Atomic Red Team' }, callback=decision_1, name="Format_ART_Command", parent_action=action)

    return

def Post_End_Event_to_Splunk(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('post_data_2() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'post_data_2' call
    results_data_1 = phantom.collect2(container=container, datapath=['Post_Start_Event_to_Splunk:action_result.parameter.host', 'Post_Start_Event_to_Splunk:action_result.parameter.source_type', 'Post_Start_Event_to_Splunk:action_result.parameter.source', 'Post_Start_Event_to_Splunk:action_result.parameter.context.artifact_id', 'Post_Start_Event_to_Splunk:action_result.parameter.data', 'Post_Start_Event_to_Splunk:action_result.parameter.index'], action_results=results)
    formatted_data_1 = phantom.get_format_data(name='format_4')

    parameters = []
    
    # build parameters list for 'post_data_2' call
    for results_item_1 in results_data_1:
        data_json = results_item_1[4]
        data = json.loads(data_json)
        data['msg'] = formatted_data_1
        data_json = json.dumps(data)
        parameters.append({
            'index': results_item_1[5],
            'host': results_item_1[0],
            'source_type': results_item_1[1],
            'data': data_json,
            'source': results_item_1[2],
            # context (artifact id) is added to associate results with the artifact
            'context': {'artifact_id': results_item_1[3]},
        })

    phantom.act("post data", parameters=parameters, app={ "name": 'Splunk' }, name="Post_End_Event_to_Splunk")

    return

def Format_End_Event(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('format_4() called')
    
    template = """Finished red team test: {0} on machine with IP address: {1}"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.act",
        "artifact:*.cef.destinationAddress",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_4")

    Post_End_Event_to_Splunk(container=container)

    return

def Run_End_Marker(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('Run_End_Marker() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Run_End_Marker' call
    results_data_1 = phantom.collect2(container=container, datapath=['Run_Start_Marker:action_result.parameter.ip_hostname', 'Run_Start_Marker:action_result.parameter.context.artifact_id'], action_results=results)
    formatted_data_1 = phantom.get_format_data(name='Format_End_Marker')

    parameters = []
    
    # build parameters list for 'Run_End_Marker' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'shell_id': "",
                'parser': "",
                'ip_hostname': results_item_1[0],
                'async': "",
                'script_str': formatted_data_1,
                'script_file': "",
                'command_id': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[1]},
            })

    phantom.act("run script", parameters=parameters, app={ "name": 'Windows Remote Management' }, callback=Format_End_Event, name="Run_End_Marker")

    return

def decision_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('decision_2() called')

    # check for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["artifact:*.cef.os", "==", "windows"],
        ])

    # call connected blocks if condition 1 matched
    if matched_artifacts_1 or matched_results_1:
        Format_Start_Marker(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'elif' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["artifact:*.cef.os", "==", "linux"],
        ])

    # call connected blocks if condition 2 matched
    if matched_artifacts_2 or matched_results_2:
        TODO_Run_Linux_Test(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'elif' condition 3
    matched_artifacts_3, matched_results_3 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["artifact:*.cef.os", "==", "macos"],
        ])

    # call connected blocks if condition 3 matched
    if matched_artifacts_3 or matched_results_3:
        TODO_Run_Mac_Test(action=action, success=success, container=container, results=results, handle=handle)
        return

    return

def TODO_Run_Linux_Test(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('TODO_Run_Linux_Test() called')

    phantom.set_status(container=container, status="closed")

    return

def TODO_Run_Mac_Test(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('TODO_Run_Mac_Test() called')

    phantom.set_status(container=container, status="closed")

    return

def Format_Start_Event(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('format_3() called')
    
    template = """Started red team test: {0} on machine with IP address: {1}"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.act",
        "artifact:*.cef.destinationAddress",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_3")

    Post_Start_Event_to_Splunk(container=container)

    return

def Run_User_Supplied_Cmd(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('Run_User_Supplied_Cmd() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Run_User_Supplied_Cmd' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.command', 'artifact:*.id'])
    results_data_1 = phantom.collect2(container=container, datapath=['Run_Start_Marker:action_result.parameter.ip_hostname', 'Run_Start_Marker:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'Run_User_Supplied_Cmd' call
    for container_item in container_data:
        for results_item_1 in results_data_1:
            if results_item_1[0]:
                parameters.append({
                    'shell_id': "",
                    'parser': "",
                    'ip_hostname': results_item_1[0],
                    'command': container_item[0],
                    'arguments': "",
                    'async': "",
                    'command_id': "",
                    # context (artifact id) is added to associate results with the artifact
                    'context': {'artifact_id': results_item_1[1]},
                })

    phantom.act("run command", parameters=parameters, app={ "name": 'Windows Remote Management' }, callback=join_Format_End_Marker, name="Run_User_Supplied_Cmd")

    return

def Format_Start_Marker(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('format_1() called')
    
    playbook_info = phantom.get_playbook_info()
    guid = phantom.get_data(playbook_info[0]['id'], clear_data=False)
    
    template = "eventcreate /id 999 /D \"started test on {0} guid=%s\" /T INFORMATION /L application" % guid

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.destinationAddress"
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Format_Start_Marker")

    Run_Start_Marker(container=container)

    return

def Post_Start_Event_to_Splunk(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('post_data_1() called')
    import platform
    import uuid

    # collect data for 'post_data_1' call
    formatted_data_1 = phantom.get_format_data(name='format_3')

    parameters = []
    
    splunk_status_index_list = phantom.collect(container, "artifact:*.cef.splunk_status_index")
    if len(splunk_status_index_list) > 0:
        splunk_status_index = str(splunk_status_index_list[0])
    else:
        splunk_status_index = "default"
    
    splunk_status_source_type_list = phantom.collect(container, "artifact:*.cef.splunk_status_source_type")
    if len(splunk_status_source_type_list) > 0:
        splunk_status_source_type = str(splunk_status_source_type_list[0])
    else:
        splunk_status_source_type = "advsim:atr"
    
    try:
        guid = phantom.collect(container, "artifact:*.cef.request")[0]
    except:
        guid = uuid.uuid4().hex
    playbook_info = phantom.get_playbook_info()
    phantom.save_data(guid, playbook_info[0]['id'])
    source = playbook_info[0]['name']
    data = {}
    data['msg'] = formatted_data_1
    data['guid'] = guid
    data['playbook_info'] = playbook_info[0]
    data_json = json.dumps(data)

    # build parameters list for 'post_data_1' call
    parameters.append({
        'index': splunk_status_index,
        'host': platform.node(),
        'source_type': splunk_status_source_type,
        'data': data_json,
        'source': source,
    })

    phantom.act("post data", parameters=parameters, app={ "name": 'Splunk' }, callback=decision_2, name="Post_Start_Event_to_Splunk")

    return

def Run_Start_Marker(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('Run_Start_Marker() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Run_Start_Marker' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.destinationAddress', 'artifact:*.id'])
    formatted_data_1 = phantom.get_format_data(name='Format_Start_Marker')

    parameters = []
    
    # build parameters list for 'Run_Start_Marker' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'shell_id': "",
                'parser': "",
                'ip_hostname': container_item[0],
                'async': "",
                'script_str': formatted_data_1,
                'script_file': "",
                'command_id': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act("run script", parameters=parameters, app={ "name": 'Windows Remote Management' }, callback=Format_ART_Command, name="Run_Start_Marker")

    return

def Run_Powershell_Test(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('Run_Powershell_Test() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Run_Powershell_Test' call
    results_data_1 = phantom.collect2(container=container, datapath=['Run_Start_Marker:action_result.parameter.ip_hostname', 'Run_Start_Marker:action_result.parameter.context.artifact_id'], action_results=results)
    filtered_results_data_1 = phantom.collect2(container=container, datapath=["filtered-data:filter_1:condition_1:Format_ART_Command:action_result.data.*.executor.command", "filtered-data:filter_1:condition_1:Format_ART_Command:action_result.parameter.context.artifact_id"])

    parameters = []
    
    # build parameters list for 'Run_Powershell_Test' call
    for results_item_1 in results_data_1:
        for filtered_results_item_1 in filtered_results_data_1:
            if results_item_1[0]:
                parameters.append({
                    'ip_hostname': results_item_1[0],
                    'script_file': "",
                    'script_str': filtered_results_item_1[0],
                    'parser': "",
                    'async': "",
                    'command_id': "",
                    'shell_id': "",
                    # context (artifact id) is added to associate results with the artifact
                    'context': {'artifact_id': results_item_1[1]},
                })

    phantom.act("run script", parameters=parameters, app={ "name": 'Windows Remote Management' }, callback=filter_2, name="Run_Powershell_Test")

    return

def Run_Cmd_Test(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('Run_Cmd_Test() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Run_Cmd_Test' call
    results_data_1 = phantom.collect2(container=container, datapath=['Run_Start_Marker:action_result.parameter.ip_hostname', 'Run_Start_Marker:action_result.parameter.context.artifact_id'], action_results=results)
    results_data_2 = phantom.collect2(container=container, datapath=["filtered-data:filter_1:condition_2:Format_ART_Command:action_result.data.*.executor.command", "filtered-data:filter_1:condition_2:Format_ART_Command:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []
    
    # build parameters list for 'Run_Cmd_Test' call
    for results_item_1 in results_data_1:
        for results_item_2 in results_data_2:
            phantom.debug(results_item_2[0])
            if '\n' in results_item_2[0]:
                cmd_list = results_item_2[0].split('\n')
                for each_cmd in cmd_list:
                    if ' ' in each_cmd:
                        parameters.append({
                            'ip_hostname': results_item_1[0],
                            'command': each_cmd.split(' ', 1)[0],
                            'arguments': each_cmd.split(' ', 1)[1],
                            'parser': "",
                            'async': True,
                            'command_id': "",
                            'shell_id': "",
                            # context (artifact id) is added to associate results with the artifact
                            'context': {'artifact_id': results_item_1[1]},
                        })
                    else:
                        parameters.append({
                            'ip_hostname': results_item_1[0],
                            'command': each_cmd,
                            'arguments': "",
                            'parser': "",
                            'async': True,
                            'command_id': "",
                            'shell_id': "",
                            # context (artifact id) is added to associate results with the artifact
                            'context': {'artifact_id': results_item_1[1]},
                        })
            else:
                parameters.append({
                    'ip_hostname': results_item_1[0],
                    'command': results_item_2[0].split(' ', 1)[0],
                    'arguments': results_item_2[0].split(' ', 1)[1],
                    'parser': "",
                    'async': True,
                    'command_id': "",
                    'shell_id': "",
                    # context (artifact id) is added to associate results with the artifact
                    'context': {'artifact_id': results_item_1[1]},
                })
    phantom.debug(parameters)

    phantom.act("run command", parameters=parameters, app={ "name": 'Windows Remote Management' }, callback=filter_3, name="Run_Cmd_Test")

    return

def Format_End_Marker(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('Format_End_Marker() called')
    
    playbook_info = phantom.get_playbook_info()
    guid = phantom.get_data(playbook_info[0]['id'], clear_data=False)
    phantom.debug(guid)
        
    template = "eventcreate /id 999 /D \"ended test for {0} guid=%s\" /T INFORMATION /L application" % guid

    # parameter list for template variable replacement
    parameters = [
        "Run_Start_Marker:action_result.parameter.ip_hostname",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Format_End_Marker")

    Run_End_Marker(container=container)

    return

def join_Format_End_Marker(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('join_Format_End_Marker() called')
    
    # if the joined function has already been called, do nothing
    if phantom.get_run_data(key='join_Format_End_Marker_called'):
        return
    
    if phantom.get_run_data(key='powershell_test') and phantom.get_run_data(key='cmd_test'):
        if phantom.get_run_data(key='powershell_error') and phantom.get_run_data(key='cmd_error'):
            if phantom.actions_done([ 'Post_Error_Msg', 'Post_Error_Msg_2' ]):
                phantom.save_run_data(key='join_Format_End_Marker_called', value='Format_End_Marker')
        
                # call connected block "Format_End_Marker"
                Format_End_Marker(container=container, handle=handle)
        elif phantom.get_run_data(key='cmd_error'): 
            if phantom.actions_done([ 'Post_Error_Msg_2', 'Run_Powershell_Test']):
                phantom.save_run_data(key='join_Format_End_Marker_called', value='Format_End_Marker')
        
                # call connected block "Format_End_Marker"
                Format_End_Marker(container=container, handle=handle)
        elif phantom.get_run_data(key='powershell_error'): 
            if phantom.actions_done([ 'Post_Error_Msg', 'Run_Cmd_Test' ]):
                phantom.save_run_data(key='join_Format_End_Marker_called', value='Format_End_Marker')
        
                # call connected block "Format_End_Marker"
                Format_End_Marker(container=container, handle=handle)
        elif phantom.actions_done([ 'Run_Powershell_Test', 'Run_Cmd_Test' ]):
                phantom.save_run_data(key='join_Format_End_Marker_called', value='Format_End_Marker')
        
                # call connected block "Format_End_Marker"
                Format_End_Marker(container=container, handle=handle)
                
    elif phantom.get_run_data(key='powershell_test'):
        if phantom.get_run_data(key='powershell_error') and phantom.actions_done([ 'Post_Error_Msg' ]):
            phantom.save_run_data(key='join_Format_End_Marker_called', value='Format_End_Marker')
        
            # call connected block "Format_End_Marker"
            Format_End_Marker(container=container, handle=handle)
            
        elif phantom.actions_done([ 'Run_Powershell_Test' ]):
            phantom.save_run_data(key='join_Format_End_Marker_called', value='Format_End_Marker')
        
            # call connected block "Format_End_Marker"
            Format_End_Marker(container=container, handle=handle)
            
    elif phantom.get_run_data(key='cmd_test'):
        if phantom.get_run_data(key='cmd_error') and phantom.actions_done([ 'Post_Error_Msg_2' ]):
            phantom.save_run_data(key='join_Format_End_Marker_called', value='Format_End_Marker')
        
            # call connected block "Format_End_Marker"
            Format_End_Marker(container=container, handle=handle)
            
        elif phantom.actions_done([ 'Run_Cmd_Test' ]):
            phantom.save_run_data(key='join_Format_End_Marker_called', value='Format_End_Marker')
        
            # call connected block "Format_End_Marker"
            Format_End_Marker(container=container, handle=handle)

    return

def filter_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('filter_1() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["Format_ART_Command:action_result.data.*.executor.name", "==", "powershell"],
        ],
        name="filter_1:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        phantom.save_run_data(value='present', key='powershell_test', auto=True)
        Run_Powershell_Test(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["Format_ART_Command:action_result.data.*.executor.name", "==", "command_prompt"],
        ],
        name="filter_1:condition_2")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        phantom.save_run_data(value='present', key='cmd_test', auto=True)
        Run_Cmd_Test(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    return

def filter_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('filter_2() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["Run_Powershell_Test:action_result.data.*.status_code", "!=", 0],
        ],
        name="filter_2:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        phantom.save_run_data(value='present', key='powershell_error', auto=True)
        Post_Error_Msg(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["Run_Powershell_Test:action_result.data.*.status_code", "==", 0],
        ],
        name="filter_2:condition_2")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        join_Format_End_Marker(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    return

def Post_Error_Msg(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('Post_Error_Msg() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Post_Error_Msg' call
    results_data_1 = phantom.collect2(container=container, datapath=['Post_Start_Event_to_Splunk:action_result.parameter.data', 'Post_Start_Event_to_Splunk:action_result.parameter.host', 'Post_Start_Event_to_Splunk:action_result.parameter.source', 'Post_Start_Event_to_Splunk:action_result.parameter.source_type', 'Post_Start_Event_to_Splunk:action_result.parameter.index', 'Post_Start_Event_to_Splunk:action_result.parameter.context.artifact_id'], action_results=results)
    
    id_value = container.get('id', None)

    parameters = []
    
    # build parameters list for 'Post_Error_Msg' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            phantom.debug(results_item_1[0])
            results_item_1[0] = json.loads(results_item_1[0])
            results_item_1[0] = {"guid": results_item_1[0]["guid"], "msg": "Likely error in powershell script run on endpoint. See Phantom event {0} for more details.".format(id_value)}
            parameters.append({
                'data': results_item_1[0],
                'host': results_item_1[1],
                'source': results_item_1[2],
                'source_type': results_item_1[3],
                'index': results_item_1[4],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[5]},
            })

    phantom.act("post data", parameters=parameters, app={ "name": 'Splunk' }, callback=join_Format_End_Marker, name="Post_Error_Msg")

    return

def filter_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('filter_3() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["Run_Cmd_Test:action_result.data.*.status_code", "!=", 0],
        ],
        name="filter_3:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        phantom.save_run_data(value='present', key='cmd_error', auto=True)
        Post_Error_Msg_2(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["Run_Cmd_Test:action_result.data.*.status_code", "==", 0],
        ],
        name="filter_3:condition_2")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        join_Format_End_Marker(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    return

def Post_Error_Msg_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('Post_Error_Msg_2() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Post_Error_Msg_2' call
    results_data_1 = phantom.collect2(container=container, datapath=['Post_Start_Event_to_Splunk:action_result.parameter.data', 'Post_Start_Event_to_Splunk:action_result.parameter.host', 'Post_Start_Event_to_Splunk:action_result.parameter.source', 'Post_Start_Event_to_Splunk:action_result.parameter.source_type', 'Post_Start_Event_to_Splunk:action_result.parameter.index', 'Post_Start_Event_to_Splunk:action_result.parameter.context.artifact_id'], action_results=results)

    id_value = container.get('id', None)
    
    parameters = []
    
    # build parameters list for 'Post_Error_Msg_2' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            phantom.debug(results_item_1[0])
            results_item_1[0] = json.loads(results_item_1[0])
            results_item_1[0] = {"guid": results_item_1[0]["guid"], "msg": "Likely error in cmd.exe command run on endpoint. See Phantom event {0} for more details.".format(id_value)}
            parameters.append({
                'data': results_item_1[0],
                'host': results_item_1[1],
                'source': results_item_1[2],
                'source_type': results_item_1[3],
                'index': results_item_1[4],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[5]},
            })

    phantom.act("post data", parameters=parameters, app={ "name": 'Splunk' }, callback=join_Format_End_Marker, name="Post_Error_Msg_2")

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