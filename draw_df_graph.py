import networkx as nx
from collections import defaultdict
import matplotlib.pyplot as plt

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
# 2. Use the exact label format we use in G.add_node(label) (currently: src\nfunc)

nodes = list()
calls = list()

external_nodes = [
    {"module": "NETWORK", "src": "", "func": "", "medium": "UDP:1514", "action": "SEND"},
    {"module": "NETWORK", "src": "", "func": "", "medium": "UDP:514", "action": "RECV"},
]
nodes.append(external_nodes)

addagent_nodes = [
]
nodes.append(addagent_nodes)

addagent_calls = [
    ("src/addagent/manage_agents.c\nadd_agent", "src/shared/agent_op.c\nw_request_agent_add_local"),
    ("src/addagent/manage_agents.c\nremove_agent", "src/shared/auth_client.c\nauth_remove_agent"),
]
calls.append(addagent_calls)

agentlessd_nodes = [
    {"module": "agentlessd", "src": "src/agentlessd/lessdcom.c", "func": "lessdcom_main", "medium": "LESSD_LOCAL_SOCK", "action": "RECV"},
    {"module": "agentlessd", "src": "src/agentlessd/agentlessd.c", "func": "send_intcheck_msg", "medium": "DEFAULTQUEUE", "action": "SEND"},
    {"module": "agentlessd", "src": "src/agentlessd/agentlessd.c", "func": "send_log_msg", "medium": "DEFAULTQUEUE", "action": "SEND"},
    {"module": "agentlessd", "src": "src/agentlessd/agentlessd.c", "func": "gen_diff_alert", "medium": "DEFAULTQUEUE", "action": "SEND"},
]
nodes.append(agentlessd_nodes)

agentlessd_calls = [
    ("src/agentlessd/agentlessd.c\nAgentlessd", "src/agentlessd/agentlessd.c\nrun_periodic_cmd"),
    ("src/agentlessd/agentlessd.c\nrun_periodic_cmd", "src/agentlessd/agentlessd.c\nsend_intcheck_msg"),
    ("src/agentlessd/agentlessd.c\nrun_periodic_cmd", "src/agentlessd/agentlessd.c\nsend_log_msg"),
    ("src/agentlessd/agentlessd.c\nrun_periodic_cmd", "src/agentlessd/agentlessd.c\nsend_intcheck_msg"),
]
calls.append(agentlessd_calls)

logcollector_nodes = [
    {"module": "logcollector", "src": "src/logcollector/lccom.c", "func": "lccom_main", "medium": "LC_LOCAL_SOCK", "action": "RECV"},
    {"module": "logcollector", "src": "src/logcollector/logcollector.c", "func": "w_output_thread", "medium": "DEFAULTQUEUE", "action": "SEND"},
]
nodes.append(logcollector_nodes)

monitord_nodes = [
    {"module": "monitord", "src": "src/monitord/moncom.c", "func": "moncom_main", "medium": "MON_LOCAL_SOCK", "action": "RECV"},
    {"module": "monitord", "src": "src/monitord/monitord.c", "func": "monitor_queue_connect", "medium": "DEFAULTQUEUE", "action": "SEND"},
    {"module": "monitord", "src": "src/monitord/monitor_actions.c", "func": "monitor_send_deletion_msg", "medium": "DEFAULTQUEUE", "action": "SEND"},
    {"module": "monitord", "src": "src/monitord/monitor_actions.c", "func": "mon_send_agent_msg", "medium": "DEFAULTQUEUE", "action": "SEND"},
]
nodes.append(monitord_nodes)

authd_nodes = [
    {"module": "authd", "src": "src/os_auth/local-server.c", "func": "run_local_server", "medium": "AUTH_LOCAL_SOCK", "action": "RECV"},
    {"module": "authd", "src": "src/os_auth/key_request.c", "func": "run_key_request_main", "medium": "KEY_REQUEST_SOCK", "action": "RECV"},
    {"module": "authd", "src": "src/os_auth/key_request.c", "func": "run_key_request_main", "medium": "request_queue", "action": "SEND"},
    {"module": "authd", "src": "src/os_auth/key_request.c", "func": "key_request_dispatch_thread", "medium": "request_queue", "action": "RECV"},
]
nodes.append(authd_nodes)

authd_calls = [

]
calls.append(authd_calls)

csyslogd_nodes = [
    {"module": "csyslogd", "src": "src/os_csyslogd/csyscom.c", "func": "csyscom_main", "medium": "CSYS_LOCAL_SOCK", "action": "RECV"},
    {"module": "csyslogd", "src": "src/os_csyslogd/alert.c", "func": "OS_Alert_SendSyslog", "medium": "UDP:514", "action": "SEND"},
    {"module": "csyslogd", "src": "src/os_csyslogd/alert.c", "func": "OS_Alert_SendSyslog_JSON", "medium": "UDP:514", "action": "SEND"},
]
nodes.append(csyslogd_nodes)

csyslogd_calls = [
    ("src/os_csyslogd/csyslogd.c\nOS_CSyslogD", "src/os_csyslogd/alert.c\nOS_Alert_SendSyslog"),
    ("src/os_csyslogd/csyslogd.c\nOS_CSyslogD", "src/os_csyslogd/alert.c\nOS_Alert_SendSyslog_JSON"),
]
calls.append(csyslogd_calls)

# dbd doesn't call any of the APIs
dbd_nodes = [
]
dbd_calls = [
]

execd_nodes = [
    {"module": "execd", "src": "src/os_execd/execd.c", "func": "ExecdStart", "medium": "EXECQUEUE", "action": "RECV"},
    {"module": "execd", "src": "src/os_execd/wcom.c", "func": "wcom_main", "medium": "COM_LOCAL_SOCK", "action": "RECV"}, # RECV then SEND
    {"module": "execd", "src": "src/os_execd/config.c", "func": "getClusterConfig", "medium": "CLUSTER_SOCK", "action": "RECV"}, # SEND then RECV
]
nodes.append(execd_nodes)

integratord_nodes = [
    {"module": "integratord", "src": "src/os_integratord/intgcom.c", "func": "intgcom_main", "medium": "INTG_LOCAL_SOCK", "action": "RECV"}, # RECV then SEND
]
# TODO: jfileq
nodes.append(integratord_nodes)

maild_nodes = [
    {"module": "maild", "src": "src/os_maild/mailcom.c", "func": "mailcom_mail", "medium": "MAIL_LOCAL_SOCK", "action": "RECV"}, # RECV then SEND
]
# TODO: smtp-related dataflow
nodes.append(maild_nodes)

remoted_nodes = [
    {"module": "remoted", "src": "src/remoted/ar-forward.c", "func": "AR_Forward", "medium": "ARQUEUE", "action": "RECV"},
    {"module": "remoted", "src": "src/remoted/cfga-forward.c", "func": "SCFGA_Forward", "medium": "CFGARQUEUE", "action": "RECV"},
    {"module": "remoted", "src": "src/remoted/syslog.c", "func": "HandleSyslog", "medium": "UDP:1514", "action": "RECV"},
    {"module": "remoted", "src": "src/remoted/syslog.c", "func": "HandleSyslog", "medium": "DEFAULTQUEUE", "action": "SEND"},
    {"module": "remoted", "src": "src/remoted/secure.c", "func": "handle_incoming_data_from_udp_socket", "medium": "UDP:1514", "action": "RECV"},
    {"module": "remoted", "src": "src/remoted/secure.c", "func": "handle_incoming_data_from_udp_socket", "medium": "queue", "action": "SEND"},
    {"module": "remoted", "src": "src/remoted/secure.c", "func": "rem_handler_main", "medium": "queue", "action": "RECV"},
    {"module": "remoted", "src": "src/remoted/secure.c", "func": "HandleSecureMessage", "medium": "DEFAULTQUEUE", "action": "SEND"},
    {"module": "remoted", "src": "src/remoted/secure.c", "func": "send_key_request", "medium": "KEY_REQUEST_SOCK", "action": "SEND"},
    {"module": "remoted", "src": "src/remoted/remcom.c", "func": "remcom_main", "medium": "REMOTE_LOCAL_SOCK", "action": "RECV"},
]
nodes.append(remoted_nodes)

remoted_calls = [
    ("src/remoted/secure.c\nrem_handler_main", "src/remoted/secure.c\nHandleSecureMessage"),
    ("src/remoted/secure.c\nHandleSecureMessage", "src/remoted/manager.c\nsave_controlmsg"),
    ("src/remoted/ar-forward.c\nAR_Forward", "src/remoted/sendmsg.c\nsend_msg"),
    ("src/remoted/cfga-forward.c\nSCFGA_Forward", "src/remoted/sendmsg.c\nsend_msg"),
]
calls.append(remoted_calls)

rootcheckd_nodes = [
    {"module": "rootcheckd", "src": "src/rootcheck/run_rk_check.c", "func": "notify_rk", "medium": "DEFAULTQUEUE", "action": "SEND"},
]
nodes.append(rootcheckd_nodes)

rootcheckd_calls = [
]
calls.append(rootcheckd_calls)

shared_nodes = [
    {"module": "shared", "src": "src/shared/agent_op.c", "func": "w_send_clustered_message", "medium": "CLUSTER_SOCK", "action": "SEND"}, # SEND then RECV
]
# TODO: enrollment-related
nodes.append(shared_nodes)

syscheckd_nodes = [
    {"module": "syscheckd", "src": "src/syscheckd/syscom.c", "func": "syscom_main", "medium": "SYS_LOCAL_SOCK", "action": "RECV"},
    {"module": "syscheckd", "src": "src/syscheckd/run_check.c", "func": "fim_send_msg", "medium": "DEFAULTQUEUE", "action": "SEND"},
]
nodes.append(syscheckd_nodes)

syscheckd_calls = [
    ("src/syscheckd/main.c\nmain", "src/syscheckd/run_check.c\nstart_daemon"),
    ("src/syscheckd/run_check.c\nstart_daemon", "src/syscheckd/run_check.c\nfim_send_msg"),
]
# TODO: check audit-related code (disabled by default)
calls.append(syscheckd_calls)

wazuh_db_nodes = [
    {"module": "wazuh_db", "src": "src/wazuh_db/main.c", "func": "run_worker", "medium": "WDB_LOCAL_SOCK", "action": "RECV"}, # RECV then SEND
]
nodes.append(wazuh_db_nodes)

wazuh_modules_nodes = [
    {"module": "wazuh_modules", "src": "src/wazuh_modules/wm_control.c", "func": "send_ip", "medium": "CONTROL_SOCK", "action": "RECV"}, # RECV then SEND
    {"module": "wazuh_modules", "src": "src/wazuh_modules/wm_download.c", "func": "wm_download_main", "medium": "WM_DOWNLOAD_SOCK", "action": "RECV"}, # RECV then SEND
    {"module": "wazuh_modules", "src": "src/wazuh_modules/wm_fluent.c", "func": "wm_fluent_main", "medium": "WM_DOWNLOAD_SOCK", "action": "RECV"}, # RECV then SEND
]


analysisd_nodes = [
    {"module": "analysisd", "src": "src/analysisd/analysisd.c", "func": "ad_input_main", "medium": "DEFAULTQUEUE", "action": "RECV"},
    {"module": "analysisd", "src": "src/analysisd/analysisd.c", "func": "ad_input_main", "medium": "decode_queue_syscheck_input", "action": "SEND"},
    {"module": "analysisd", "src": "src/analysisd/analysisd.c", "func": "ad_input_main", "medium": "decode_queue_rootcheck_input", "action": "SEND"},
    {"module": "analysisd", "src": "src/analysisd/analysisd.c", "func": "ad_input_main", "medium": "decode_queue_sca_input", "action": "SEND"},
    {"module": "analysisd", "src": "src/analysisd/analysisd.c", "func": "ad_input_main", "medium": "decode_queue_syscollector_input", "action": "SEND"},
    {"module": "analysisd", "src": "src/analysisd/analysisd.c", "func": "ad_input_main", "medium": "decode_queue_hostinfo_input", "action": "SEND"},
    {"module": "analysisd", "src": "src/analysisd/analysisd.c", "func": "ad_input_main", "medium": "decode_queue_winevt_input", "action": "SEND"},
    {"module": "analysisd", "src": "src/analysisd/analysisd.c", "func": "ad_input_main", "medium": "decode_queue_event_input", "action": "SEND"},
    {"module": "analysisd", "src": "src/analysisd/analysisd.c", "func": "ad_input_main", "medium": "dispatch_dbsync_input", "action": "SEND"},
    {"module": "analysisd", "src": "src/analysisd/analysisd.c", "func": "ad_input_main", "medium": "upgrade_module_input", "action": "SEND"},
    {"module": "analysisd", "src": "src/analysisd/analysisd.c", "func": "w_decode_syscheck_thread", "medium": "decode_queue_syscheck_input", "action": "RECV"},
    {"module": "analysisd", "src": "src/analysisd/analysisd.c", "func": "w_decode_syscheck_thread", "medium": "decode_queue_event_output", "action": "SEND"},
    {"module": "analysisd", "src": "src/analysisd/analysisd.c", "func": "w_decode_rootcheck_thread", "medium": "decode_queue_rootcheck_input", "action": "RECV"},
    {"module": "analysisd", "src": "src/analysisd/analysisd.c", "func": "w_decode_rootcheck_thread", "medium": "decode_queue_event_output", "action": "SEND"},
    {"module": "analysisd", "src": "src/analysisd/analysisd.c", "func": "w_decode_sca_thread", "medium": "decode_queue_sca_input", "action": "RECV"},
    {"module": "analysisd", "src": "src/analysisd/analysisd.c", "func": "w_decode_sca_thread", "medium": "decode_queue_event_output", "action": "SEND"},
    {"module": "analysisd", "src": "src/analysisd/analysisd.c", "func": "w_decode_syscollector_thread", "medium": "decode_queue_syscollector_input", "action": "RECV"},
    {"module": "analysisd", "src": "src/analysisd/analysisd.c", "func": "w_decode_syscollector_thread", "medium": "decode_queue_event_output", "action": "SEND"},
    {"module": "analysisd", "src": "src/analysisd/analysisd.c", "func": "w_decode_hostinfo_thread", "medium": "decode_queue_hostinfo_input", "action": "RECV"},
    {"module": "analysisd", "src": "src/analysisd/analysisd.c", "func": "w_decode_hostinfo_thread", "medium": "decode_queue_event_output", "action": "SEND"},
    {"module": "analysisd", "src": "src/analysisd/analysisd.c", "func": "w_decode_winevt_thread", "medium": "decode_queue_winevt_input", "action": "RECV"},
    {"module": "analysisd", "src": "src/analysisd/analysisd.c", "func": "w_decode_winevt_thread", "medium": "decode_queue_event_output", "action": "SEND"},
    {"module": "analysisd", "src": "src/analysisd/analysisd.c", "func": "w_decode_event_thread", "medium": "decode_queue_event_input", "action": "RECV"},
    {"module": "analysisd", "src": "src/analysisd/analysisd.c", "func": "w_decode_event_thread", "medium": "decode_queue_event_output", "action": "SEND"},
    {"module": "analysisd", "src": "src/analysisd/analysisd.c", "func": "w_dispatch_dbsync_thread", "medium": "dispatch_dbsync_input", "action": "RECV"},
    {"module": "analysisd", "src": "src/analysisd/analysisd.c", "func": "w_dispatch_upgrade_module_thread", "medium": "upgrade_module_input", "action": "RECV"},
    {"module": "analysisd", "src": "src/analysisd/analysisd.c", "func": "w_dispatch_upgrade_module_thread", "medium": "WM_UPGRADE_SOCK", "action": "SEND"},
    {"module": "analysisd", "src": "src/analysisd/analysisd.c", "func": "w_process_event_thread", "medium": "decode_queue_event_output", "action": "RECV"},
    {"module": "analysisd", "src": "src/analysisd/alerts/exec.c", "func": "OS_Exec", "medium": "EXECQUEUE", "action": "SEND"},
    {"module": "analysisd", "src": "src/analysisd/alerts/exec.c", "func": "OS_Exec", "medium": "ARQUEUE", "action": "SEND"},
    {"module": "analysisd", "src": "src/analysisd/asyscom.c", "func": "asyscom_main", "medium": "ANLSYS_LOCAL_SOCK", "action": "RECV"},
]
nodes.append(analysisd_nodes)

analysisd_calls = [
    ("src/analysisd/analysisd.c\nw_process_event_thread", "src/analysisd/alerts/exec.c\nOS_Exec"),
]
calls.append(analysisd_calls)

all_nodes = list()
for node in nodes:
    all_nodes += node

all_calls = list()
for call in calls:
    all_calls += call

G = nx.DiGraph()
medium_map = defaultdict(lambda: {"SEND": [], "RECV": []})

for node in all_nodes:
    # label = f"{node['module']} ({node['src']})\node{node['func']}" if node["src"] != "" else f"{node['module']}"
    label = f"{node['src']}\n{node['func']}" if node["src"] != "" else f"{node['module']}"
    G.add_node(label)
    medium_map[node["medium"]][node["action"]].append(label)

# Add edges from each SEND to each RECV on same medium
for medium, groups in medium_map.items():
    for sender in groups["SEND"]:
        for receiver in groups["RECV"]:
            G.add_edge(sender, receiver, label=medium)

# Add edges for function calls
for call in all_calls:
    print(call)
    G.add_edge(call[0], call[1], label="call")

# pos = nx.spring_layout(G, seed=10)
# pos = nx.circular_layout(G)
pos = nx.kamada_kawai_layout(G)
plt.figure(figsize=(16, 8))

nx.draw_networkx_nodes(
    G,
    pos,
    node_size=100,
    node_shape="s",
)

nx.draw_networkx_edges(
    G,
    pos,
    arrowstyle="-|>",
    arrowsize=16,
    node_size=1000,
    connectionstyle="arc3,rad=0.1",
    edge_color="black"
)

nx.draw_networkx_labels(
    G,
    pos,
    font_size=8,
    font_family="monospace",
    bbox=dict(
        facecolor="lightsteelblue",
        edgecolor="black",
        boxstyle="round,pad=0.4"
    )
)

edge_labels = nx.get_edge_attributes(G, "label")
nx.draw_networkx_edge_labels(
    G,
    pos,
    edge_labels=edge_labels,
    font_size=8,
    font_family="monospace",
    font_color="darkred",
    font_weight="bold",
    rotate=False
)

plt.title("Wazuh Dataflow Diagram")
plt.axis("off")
# plt.tight_layout()
plt.margins(x=1.0)
plt.show()

