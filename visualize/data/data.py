# import matplotlib.pyplot as plt

# # Wazuh Dataflow Graph Plotter
# ## Targets
# 1. Queue
# - Types:
#   - {DEFAULT, EXEC, CFGA, CFGAR, AR}QUEUE
#   - KEY_REQUEST_SOCK
# - Init:
#   - StartMQ, StartMQWithSpecificOwnerAndPerms
# - APIs:
#  - SendMSG, SendMSGPredicated, SendMSGtoSCK, OS_SendUnix
#  - OS_ReadMSG, OS_RecvUnix
#
# 2. Socket
# - Types:
#   - {AUTH, COM, LC, SYS, WM, REMOTE, ANLSYS, MAIL, LESSD, INTG, CSYS, MON, WDB}_LOCAL_SOCK
#   - {CLUSTER, CONTROL, LOGTEST, AGENT_UPGRADE, WM_DOWNLOAD, WM_UPGRADE, WM_TASK_MODULE}_SOCK,
#   - TASK_QUEUE
# - Init:
#   - OS_BindUnixDomain, OS_BindUnixDomainWithPerms (local)
#   - OS_ConnectUnixDomain (remote)
# - APIs:
#   - OS_SendSecureTCP, send
#   - OS_RecvSecureTCP, OS_RecvUnix, recv
#
# 3. Network
# - Init:
#   - OS_BindPortudp, OS_BindPorttcp
# - APIs:
#   - recvfrom, sendto
#
# ## TODO
# 1. Search for (i.e., grep) the target Types and APIs in each module directory
#    then populate {module}_nodes and {module}_calls.
# 2. Prettify graph

# Note on {module}_nodes
# func: The function that calls send/recv APIs
# medium: Name (alias) of the shared var (e.g., DEFAULTQUEUE).
#         Some modules use internal queue (e.g., q = queue_init(sz);). List them too.

# Note on {module}_calls:
# 1. It's okay to skip intermediate calls
# 2. Use the exact label format we use in G.add_node(label) (currently: src<br>func)

# Example: Add a subgraph to G
# Suppose you want to add a subgraph with specific nodes and edges

external_nodes = [
    {
        "module": "NETWORK",
        "code": "",
        "func": "",
        "medium": "UDP:1514",
        "action": "SEND",
    },
    {
        "module": "NETWORK",
        "code": "",
        "func": "",
        "medium": "UDP:514",
        "action": "RECV",
    },
]

addagent_nodes = []

addagent_calls = [
    (
        "src/addagent/manage_agents.c\nadd_agent",
        "src/shared/agent_op.c\nw_request_agent_add_local",
    ),
    (
        "src/addagent/manage_agents.c\nremove_agent",
        "src/shared/auth_client.c\nauth_remove_agent",
    ),
]

agentlessd_nodes = [
    {
        "module": "agentlessd",
        "code": "src/agentlessd/lessdcom.c",
        "func": "lessdcom_main",
        "medium": "LESSD_LOCAL_SOCK",
        "action": "RECV",
    },
    {
        "module": "agentlessd",
        "code": "src/agentlessd/agentlessd.c",
        "func": "send_intcheck_msg",
        "medium": "DEFAULTQUEUE",
        "action": "SEND",
    },
    {
        "module": "agentlessd",
        "code": "src/agentlessd/agentlessd.c",
        "func": "send_log_msg",
        "medium": "DEFAULTQUEUE",
        "action": "SEND",
    },
    {
        "module": "agentlessd",
        "code": "src/agentlessd/agentlessd.c",
        "func": "gen_diff_alert",
        "medium": "DEFAULTQUEUE",
        "action": "SEND",
    },
]

agentlessd_calls = [
    (
        "src/agentlessd/agentlessd.c\nAgentlessd",
        "src/agentlessd/agentlessd.c\nrun_periodic_cmd",
    ),
    (
        "src/agentlessd/agentlessd.c\nrun_periodic_cmd",
        "src/agentlessd/agentlessd.c\nsend_intcheck_msg",
    ),
    (
        "src/agentlessd/agentlessd.c\nrun_periodic_cmd",
        "src/agentlessd/agentlessd.c\nsend_log_msg",
    ),
    (
        "src/agentlessd/agentlessd.c\nrun_periodic_cmd",
        "src/agentlessd/agentlessd.c\nsend_intcheck_msg",
    ),
]

logcollector_nodes = [
    {
        "module": "logcollector",
        "code": "src/logcollector/lccom.c",
        "func": "lccom_main",
        "medium": "LC_LOCAL_SOCK",
        "action": "RECV",
    },
    {
        "module": "logcollector",
        "code": "src/logcollector/logcollector.c",
        "func": "w_output_thread",
        "medium": "DEFAULTQUEUE",
        "action": "SEND",
    },
]

monitord_nodes = [
    {
        "module": "monitord",
        "code": "src/monitord/moncom.c",
        "func": "moncom_main",
        "medium": "MON_LOCAL_SOCK",
        "action": "RECV",
    },
    {
        "module": "monitord",
        "code": "src/monitord/monitord.c",
        "func": "monitor_queue_connect",
        "medium": "DEFAULTQUEUE",
        "action": "SEND",
    },
    {
        "module": "monitord",
        "code": "src/monitord/monitor_actions.c",
        "func": "monitor_send_deletion_msg",
        "medium": "DEFAULTQUEUE",
        "action": "SEND",
    },
    {
        "module": "monitord",
        "code": "src/monitord/monitor_actions.c",
        "func": "mon_send_agent_msg",
        "medium": "DEFAULTQUEUE",
        "action": "SEND",
    },
]

authd_nodes = [
    {
        "module": "authd",
        "code": "src/os_auth/local-server.c",
        "func": "run_local_server",
        "medium": "AUTH_LOCAL_SOCK",
        "action": "RECV",
    },
    {
        "module": "authd",
        "code": "src/os_auth/key_request.c",
        "func": "run_key_request_main",
        "medium": "KEY_REQUEST_SOCK",
        "action": "RECV",
    },
    {
        "module": "authd",
        "code": "src/os_auth/key_request.c",
        "func": "run_key_request_main",
        "medium": "request_queue",
        "action": "SEND",
    },
    {
        "module": "authd",
        "code": "src/os_auth/key_request.c",
        "func": "key_request_dispatch_thread",
        "medium": "request_queue",
        "action": "RECV",
    },
]

authd_calls = []

csyslogd_nodes = [
    {
        "module": "csyslogd",
        "code": "src/os_csyslogd/csyscom.c",
        "func": "csyscom_main",
        "medium": "CSYS_LOCAL_SOCK",
        "action": "RECV",
    },
    {
        "module": "csyslogd",
        "code": "src/os_csyslogd/alert.c",
        "func": "OS_Alert_SendSyslog",
        "medium": "UDP:514",
        "action": "SEND",
    },
    {
        "module": "csyslogd",
        "code": "src/os_csyslogd/alert.c",
        "func": "OS_Alert_SendSyslog_JSON",
        "medium": "UDP:514",
        "action": "SEND",
    },
]

csyslogd_calls = [
    (
        "src/os_csyslogd/csyslogd.c\nOS_CSyslogD",
        "src/os_csyslogd/alert.c\nOS_Alert_SendSyslog",
    ),
    (
        "src/os_csyslogd/csyslogd.c\nOS_CSyslogD",
        "src/os_csyslogd/alert.c\nOS_Alert_SendSyslog_JSON",
    ),
]

# dbd doesn't call any of the APIs
dbd_nodes = []
dbd_calls = []

execd_nodes = [
    {
        "module": "execd",
        "code": "src/os_execd/execd.c",
        "func": "ExecdStart",
        "medium": "EXECQUEUE",
        "action": "RECV",
    },
    {
        "module": "execd",
        "code": "src/os_execd/wcom.c",
        "func": "wcom_main",
        "medium": "COM_LOCAL_SOCK",
        "action": "RECV",
    },  # RECV then SEND
    {
        "module": "execd",
        "code": "src/os_execd/config.c",
        "func": "getClusterConfig",
        "medium": "CLUSTER_SOCK",
        "action": "RECV",
    },  # SEND then RECV
]

integratord_nodes = [
    {
        "module": "integratord",
        "code": "src/os_integratord/intgcom.c",
        "func": "intgcom_main",
        "medium": "INTG_LOCAL_SOCK",
        "action": "RECV",
    },  # RECV then SEND
]
# TODO: jfileq

maild_nodes = [
    {
        "module": "maild",
        "code": "src/os_maild/mailcom.c",
        "func": "mailcom_mail",
        "medium": "MAIL_LOCAL_SOCK",
        "action": "RECV",
    },  # RECV then SEND
]
# TODO: smtp-related dataflow

remoted_nodes = [
    {
        "module": "remoted",
        "code": "src/remoted/ar-forward.c",
        "func": "AR_Forward",
        "medium": "ARQUEUE",
        "action": "RECV",
    },
    {
        "module": "remoted",
        "code": "src/remoted/cfga-forward.c",
        "func": "SCFGA_Forward",
        "medium": "CFGARQUEUE",
        "action": "RECV",
    },
    {
        "module": "remoted",
        "code": "src/remoted/syslog.c",
        "func": "HandleSyslog",
        "medium": "UDP:1514",
        "action": "RECV",
    },
    {
        "module": "remoted",
        "code": "src/remoted/syslog.c",
        "func": "HandleSyslog",
        "medium": "DEFAULTQUEUE",
        "action": "SEND",
    },
    {
        "module": "remoted",
        "code": "src/remoted/secure.c",
        "func": "handle_incoming_data_from_udp_socket",
        "medium": "UDP:1514",
        "action": "RECV",
    },
    {
        "module": "remoted",
        "code": "src/remoted/secure.c",
        "func": "handle_incoming_data_from_udp_socket",
        "medium": "queue",
        "action": "SEND",
    },
    {
        "module": "remoted",
        "code": "src/remoted/secure.c",
        "func": "rem_handler_main",
        "medium": "queue",
        "action": "RECV",
    },
    {
        "module": "remoted",
        "code": "src/remoted/secure.c",
        "func": "HandleSecureMessage",
        "medium": "DEFAULTQUEUE",
        "action": "SEND",
    },
    {
        "module": "remoted",
        "code": "src/remoted/secure.c",
        "func": "send_key_request",
        "medium": "KEY_REQUEST_SOCK",
        "action": "SEND",
    },
    {
        "module": "remoted",
        "code": "src/remoted/remcom.c",
        "func": "remcom_main",
        "medium": "REMOTE_LOCAL_SOCK",
        "action": "RECV",
    },
]

remoted_calls = [
    (
        "src/remoted/secure.c\nrem_handler_main",
        "src/remoted/secure.c\nHandleSecureMessage",
    ),
    (
        "src/remoted/secure.c\nHandleSecureMessage",
        "src/remoted/manager.c\nsave_controlmsg",
    ),
    ("src/remoted/ar-forward.c\nAR_Forward", "src/remoted/sendmsg.c\nsend_msg"),
    (
        "src/remoted/cfga-forward.c\nSCFGA_Forward",
        "src/remoted/sendmsg.c\nsend_msg",
    ),
]

rootcheckd_nodes = [
    {
        "module": "rootcheckd",
        "code": "src/rootcheck/run_rk_check.c",
        "func": "notify_rk",
        "medium": "DEFAULTQUEUE",
        "action": "SEND",
    },
]

rootcheckd_calls = []

shared_nodes = [
    {
        "module": "shared",
        "code": "src/shared/agent_op.c",
        "func": "w_send_clustered_message",
        "medium": "CLUSTER_SOCK",
        "action": "SEND",
    },  # SEND then RECV
]
# TODO: enrollment-related

syscheckd_nodes = [
    {
        "module": "syscheckd",
        "code": "src/syscheckd/syscom.c",
        "func": "syscom_main",
        "medium": "SYS_LOCAL_SOCK",
        "action": "RECV",
    },
    {
        "module": "syscheckd",
        "code": "src/syscheckd/run_check.c",
        "func": "fim_send_msg",
        "medium": "DEFAULTQUEUE",
        "action": "SEND",
    },
]

syscheckd_calls = [
    ("src/syscheckd/main.c\nmain", "src/syscheckd/run_check.c\nstart_daemon"),
    (
        "src/syscheckd/run_check.c\nstart_daemon",
        "src/syscheckd/run_check.c\nfim_send_msg",
    ),
]
# TODO: check audit-related code (disabled by default)

wazuh_db_nodes = [
    {
        "module": "wazuh_db",
        "code": "src/wazuh_db/main.c",
        "func": "run_worker",
        "medium": "WDB_LOCAL_SOCK",
        "action": "RECV",
    },  # RECV then SEND
]

wazuh_modules_nodes = [
    {
        "module": "wazuh_modules",
        "code": "src/wazuh_modules/wm_control.c",
        "func": "send_ip",
        "medium": "CONTROL_SOCK",
        "action": "RECV",
    },  # RECV then SEND
    {
        "module": "wazuh_modules",
        "code": "src/wazuh_modules/wm_download.c",
        "func": "wm_download_main",
        "medium": "WM_DOWNLOAD_SOCK",
        "action": "RECV",
    },  # RECV then SEND
    {
        "module": "wazuh_modules",
        "code": "src/wazuh_modules/wm_fluent.c",
        "func": "wm_fluent_main",
        "medium": "WM_DOWNLOAD_SOCK",
        "action": "RECV",
    },  # RECV then SEND
    {
        "module": "wazuh_modules",
        "code": "src/wazuh_modules/wmcom.c",
        "func": "wmcom_main",
        "medium": "WM_LOCAL_SOCK",
        "action": "RECV",
    },  # RECV then SEND
    {
        "module": "wazuh_modules",
        "code": "src/wazuh_modules/wmcom.c",
        "func": "wmcom_send",
        "medium": "WM_LOCAL_SOCK",
        "action": "SEND",
    },
    {
        "module": "wazuh_modules",
        "code": "src/wazuh_modules/agent_upgrade/agent/wm_agent_upgrade_agent.c",
        "func": "wm_agent_upgrade_listen_messages",
        "medium": "AGENT_UPGRADE_SOCK",
        "action": "RECV",
    },  # RECV then SEND
    {
        "module": "wazuh_modules",
        "code": "src/wazuh_modules/agent_upgrade/manager/wm_agent_upgrade_manager.c",
        "func": "wm_agent_upgrade_listen_messages",
        "medium": "WM_UPGRADE_SOCK",
        "action": "RECV",
    },  # RECV then SEND
    {
        "module": "wazuh_modules",
        "code": "src/wazuh_modules/agent_upgrade/manager/wm_agent_upgrade_tasks.c",
        "func": "wm_agent_send_task_information_master",
        "medium": "WM_TASK_MODULE_SOCK",
        "action": "SEND",
    },  # SEND then RECV
    {
        "module": "wazuh_modules",
        "code": "src/wazuh_modules/agent_upgrade/manager/wm_agent_upgrade_upgrades.c",
        "func": "wm_agent_upgrade_send_command_to_agent",
        "medium": "REMOTE_LOCAL_SOCK",
        "action": "SEND",
    },  # SEND then RECV
    {
        "module": "wazuh_modules",
        "code": "src/wazuh_modules/task_manager/wm_task_manager.c",
        "func": "wm_task_manager_main",
        "medium": "TASK_QUEUE",
        "action": "RECV",
    },  # RECV then SEND
    {
        "module": "wazuh_modules",
        "code": "src/wazuh_modules/wmodules.c",
        "func": "wm_sendmsg",
        "medium": "DEFAULTQUEUE",
        "action": "SEND",
    },
    {
        "module": "wazuh_modules",
        "code": "src/wazuh_modules/wmodules.c",
        "func": "wm_sendmsg_ex",
        "medium": "DEFAULTQUEUE",
        "action": "SEND",
    },
    {
        "module": "wazuh_modules",
        "code": "src/wazuh_modules/wm_azure.c",
        "func": "wm_azure_main",
        "medium": "DEFAULTQUEUE",
        "action": "SEND",
    },
    {
        "module": "wazuh_modules",
        "code": "src/wazuh_modules/wm_oscap.c",
        "func": "wm_oscap_run",
        "medium": "DEFAULTQUEUE",
        "action": "SEND",
    },
]
# TODO: add VulnerabilityScanner

wazuh_modules_calls = [
    (
        "src/wazuh_modules/wm_aws.c\nwm_aws_run_s3",
        "src/wazuh_modules/wmodules.c\nwm_sendmsg",
    ),
    (
        "src/wazuh_modules/wm_aws.c\nwm_aws_run_service",
        "src/wazuh_modules/wmodules.c\nwm_sendmsg",
    ),
    (
        "src/wazuh_modules/wm_aws.c\nwm_aws_run_subscriber",
        "src/wazuh_modules/wmodules.c\nwm_sendmsg",
    ),
    (
        "src/wazuh_modules/wm_command.c\nwm_command_main",
        "src/wazuh_modules/wmodules.c\nwm_sendmsg",
    ),
    (
        "src/wazuh_modules/wm_github.c\nwm_github_execute_scan",
        "src/wazuh_modules/wmodules.c\nwm_sendmsg",
    ),
    (
        "src/wazuh_modules/wm_github.c\nwm_github_execute_scan",
        "src/wazuh_modules/wmodules.c\nwm_github_scan_failure_action",
    ),
    (
        "src/wazuh_modules/wm_github.c\nwm_github_scan_failure_action",
        "src/wazuh_modules/wmodules.c\nwm_sendmsg",
    ),
    (
        "src/wazuh_modules/wm_ms_graph.c\nwm_ms_graph_scan_relationships",
        "src/wazuh_modules/wmodules.c\nwm_sendmsg",
    ),
    (
        "src/wazuh_modules/wm_office365.c\nwm_office365_execute_scan",
        "src/wazuh_modules/wmodules.c\nwm_sendmsg",
    ),
    (
        "src/wazuh_modules/wm_office365.c\nwm_office365_execute_scan",
        "src/wazuh_modules/wmodules.c\nwm_office365_scan_failure_action",
    ),
    (
        "src/wazuh_modules/wm_oscap.c\nwm_oscap_run",
        "src/wazuh_modules/wmodules.c\nwm_sendmsg",
    ),
    (
        "src/wazuh_modules/wm_osquery_monitor.c\nRead_Log",
        "src/wazuh_modules/wmodules.c\nwm_sendmsg",
    ),
    (
        "src/wazuh_modules/wm_osquery_monitor.c\nExecute_Osquery",
        "src/wazuh_modules/wmodules.c\nwm_sendmsg",
    ),
    (
        "src/wazuh_modules/wm_sca.c\nwm_sca_send_summary",
        "src/wazuh_modules/wm_sca.c\nwm_sca_send_alert",
    ),
    (
        "src/wazuh_modules/wm_sca.c\nwm_sca_send_event_check",
        "src/wazuh_modules/wm_sca.c\nwm_sca_send_alert",
    ),
    (
        "src/wazuh_modules/wm_sca.c\nwm_sca_send_policies_scanned",
        "src/wazuh_modules/wm_sca.c\nwm_sca_send_alert",
    ),
    (
        "src/wazuh_modules/wm_sca.c\nwm_sca_dump_db_thread",
        "src/wazuh_modules/wm_sca.c\nwm_sca_send_alert",
    ),
    (
        "src/wazuh_modules/wm_sca.c\nwm_sca_send_dump_end",
        "src/wazuh_modules/wm_sca.c\nwm_sca_send_alert",
    ),
    (
        "src/wazuh_modules/wm_sca.c\nwm_sca_send_alert",
        "src/wazuh_modules/wmodules.c\nwm_sendmsg",
    ),
    (
        "src/wazuh_modules/wm_syscollector.c\nwm_sys_send_message",
        "src/wazuh_modules/wmodules.c\nwm_sendmsg_ex",
    ),
    (
        "src/wazuh_modules/agent_upgrade/agent/wm_agent_upgrade_agent.c\nwm_upgrade_agent_search_upgrade_result",
        "src/wazuh_modules/agent_upgrade/agent/wm_agent_upgrade_agent.c\nwm_upgrade_agent_send_ack_message",
    ),
    (
        "src/wazuh_modules/agent_upgrade/agent/wm_agent_upgrade_agent.c\nwm_upgrade_agent_send_ack_message",
        "src/wazuh_modules/wmodules.c\nwm_sendmsg",
    ),
]

analysisd_nodes = [
    {
        "module": "analysisd",
        "code": "src/analysisd/analysisd.c",
        "func": "ad_input_main",
        "medium": "DEFAULTQUEUE",
        "action": "RECV",
    },
    {
        "module": "analysisd",
        "code": "src/analysisd/analysisd.c",
        "func": "ad_input_main",
        "medium": "decode_queue_syscheck_input",
        "action": "SEND",
    },
    {
        "module": "analysisd",
        "code": "src/analysisd/analysisd.c",
        "func": "ad_input_main",
        "medium": "decode_queue_rootcheck_input",
        "action": "SEND",
    },
    {
        "module": "analysisd",
        "code": "src/analysisd/analysisd.c",
        "func": "ad_input_main",
        "medium": "decode_queue_sca_input",
        "action": "SEND",
    },
    {
        "module": "analysisd",
        "code": "src/analysisd/analysisd.c",
        "func": "ad_input_main",
        "medium": "decode_queue_syscollector_input",
        "action": "SEND",
    },
    {
        "module": "analysisd",
        "code": "src/analysisd/analysisd.c",
        "func": "ad_input_main",
        "medium": "decode_queue_hostinfo_input",
        "action": "SEND",
    },
    {
        "module": "analysisd",
        "code": "src/analysisd/analysisd.c",
        "func": "ad_input_main",
        "medium": "decode_queue_winevt_input",
        "action": "SEND",
    },
    {
        "module": "analysisd",
        "code": "src/analysisd/analysisd.c",
        "func": "ad_input_main",
        "medium": "decode_queue_event_input",
        "action": "SEND",
    },
    {
        "module": "analysisd",
        "code": "src/analysisd/analysisd.c",
        "func": "ad_input_main",
        "medium": "dispatch_dbsync_input",
        "action": "SEND",
    },
    {
        "module": "analysisd",
        "code": "src/analysisd/analysisd.c",
        "func": "ad_input_main",
        "medium": "upgrade_module_input",
        "action": "SEND",
    },
    {
        "module": "analysisd",
        "code": "src/analysisd/analysisd.c",
        "func": "w_decode_syscheck_thread",
        "medium": "decode_queue_syscheck_input",
        "action": "RECV",
    },
    {
        "module": "analysisd",
        "code": "src/analysisd/analysisd.c",
        "func": "w_decode_syscheck_thread",
        "medium": "decode_queue_event_output",
        "action": "SEND",
    },
    {
        "module": "analysisd",
        "code": "src/analysisd/analysisd.c",
        "func": "w_decode_rootcheck_thread",
        "medium": "decode_queue_rootcheck_input",
        "action": "RECV",
    },
    {
        "module": "analysisd",
        "code": "src/analysisd/analysisd.c",
        "func": "w_decode_rootcheck_thread",
        "medium": "decode_queue_event_output",
        "action": "SEND",
    },
    {
        "module": "analysisd",
        "code": "src/analysisd/analysisd.c",
        "func": "w_decode_sca_thread",
        "medium": "decode_queue_sca_input",
        "action": "RECV",
    },
    {
        "module": "analysisd",
        "code": "src/analysisd/analysisd.c",
        "func": "w_decode_sca_thread",
        "medium": "decode_queue_event_output",
        "action": "SEND",
    },
    {
        "module": "analysisd",
        "code": "src/analysisd/analysisd.c",
        "func": "w_decode_syscollector_thread",
        "medium": "decode_queue_syscollector_input",
        "action": "RECV",
    },
    {
        "module": "analysisd",
        "code": "src/analysisd/analysisd.c",
        "func": "w_decode_syscollector_thread",
        "medium": "decode_queue_event_output",
        "action": "SEND",
    },
    {
        "module": "analysisd",
        "code": "src/analysisd/analysisd.c",
        "func": "w_decode_hostinfo_thread",
        "medium": "decode_queue_hostinfo_input",
        "action": "RECV",
    },
    {
        "module": "analysisd",
        "code": "src/analysisd/analysisd.c",
        "func": "w_decode_hostinfo_thread",
        "medium": "decode_queue_event_output",
        "action": "SEND",
    },
    {
        "module": "analysisd",
        "code": "src/analysisd/analysisd.c",
        "func": "w_decode_winevt_thread",
        "medium": "decode_queue_winevt_input",
        "action": "RECV",
    },
    {
        "module": "analysisd",
        "code": "src/analysisd/analysisd.c",
        "func": "w_decode_winevt_thread",
        "medium": "decode_queue_event_output",
        "action": "SEND",
    },
    {
        "module": "analysisd",
        "code": "src/analysisd/analysisd.c",
        "func": "w_decode_event_thread",
        "medium": "decode_queue_event_input",
        "action": "RECV",
    },
    {
        "module": "analysisd",
        "code": "src/analysisd/analysisd.c",
        "func": "w_decode_event_thread",
        "medium": "decode_queue_event_output",
        "action": "SEND",
    },
    {
        "module": "analysisd",
        "code": "src/analysisd/analysisd.c",
        "func": "w_dispatch_dbsync_thread",
        "medium": "dispatch_dbsync_input",
        "action": "RECV",
    },
    {
        "module": "analysisd",
        "code": "src/analysisd/analysisd.c",
        "func": "w_dispatch_upgrade_module_thread",
        "medium": "upgrade_module_input",
        "action": "RECV",
    },
    {
        "module": "analysisd",
        "code": "src/analysisd/analysisd.c",
        "func": "w_dispatch_upgrade_module_thread",
        "medium": "WM_UPGRADE_SOCK",
        "action": "SEND",
    },
    {
        "module": "analysisd",
        "code": "src/analysisd/analysisd.c",
        "func": "w_process_event_thread",
        "medium": "decode_queue_event_output",
        "action": "RECV",
    },
    {
        "module": "analysisd",
        "code": "src/analysisd/alerts/exec.c",
        "func": "OS_Exec",
        "medium": "EXECQUEUE",
        "action": "SEND",
    },
    {
        "module": "analysisd",
        "code": "src/analysisd/alerts/exec.c",
        "func": "OS_Exec",
        "medium": "ARQUEUE",
        "action": "SEND",
    },
    {
        "module": "analysisd",
        "code": "src/analysisd/asyscom.c",
        "func": "asyscom_main",
        "medium": "ANLSYS_LOCAL_SOCK",
        "action": "RECV",
    },
]

analysisd_calls = [
    (
        "src/analysisd/analysisd.c\nw_process_event_thread",
        "src/analysisd/alerts/exec.c\nOS_Exec",
    ),
]

nodes = (
    external_nodes
    + addagent_nodes
    + agentlessd_nodes
    + logcollector_nodes
    + monitord_nodes
    + authd_nodes
    + csyslogd_nodes
    + execd_nodes
    + integratord_nodes
    + maild_nodes
    + remoted_nodes
    + rootcheckd_nodes
    + shared_nodes
    + syscheckd_nodes
    + wazuh_db_nodes
    + wazuh_modules_nodes
    + analysisd_nodes
)

calls = (
    addagent_calls
    + agentlessd_calls
    + authd_calls
    + csyslogd_calls
    + remoted_calls
    + rootcheckd_calls
    + syscheckd_calls
    + wazuh_modules_calls
    + analysisd_calls
)

if __name__ == "__main__":
    import json

    with open("nodes.json", "w") as f:
        json.dump(nodes, f, indent=4)

    calls = [
        {
            "src_code": call[0].split("\n")[0],
            "src_func": call[0].split("\n")[1],
            "dst_code": call[1].split("\n")[0],
            "dst_func": call[1].split("\n")[1],
        }
        for call in calls
    ]
    with open("calls.json", "w") as f:
        json.dump(calls, f, indent=4)
