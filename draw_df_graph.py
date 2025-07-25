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

external_nodes = [
    {"module": "NETWORK", "src": "", "func": "", "medium": "UDP:1514", "action": "SEND"},
]

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
remoted_calls = [
    ("src/remoted/secure.c\nrem_handler_main", "src/remoted/secure.c\nHandleSecureMessage"),
    ("src/remoted/secure.c\nHandleSecureMessage", "src/remoted/manager.c\nsave_controlmsg"),
    ("src/remoted/ar-forward.c\nAR_Forward", "src/remoted/sendmsg.c\nsend_msg"),
    ("src/remoted/cfga-forward.c\nSCFGA_Forward", "src/remoted/sendmsg.c\nsend_msg"),
]

syscheckd_nodes = [
    {"module": "syscheckd", "src": "src/syscheckd/syscom.c", "func": "syscom_main", "medium": "SYS_LOCAL_SOCK", "action": "RECV"},
    {"module": "syscheckd", "src": "src/syscheckd/run_check.c", "func": "fim_send_msg", "medium": "DEFAULTQUEUE", "action": "SEND"},
]
syscheckd_calls = [
    ("src/syscheckd/main.c\nmain", "src/syscheckd/run_check.c\nstart_daemon"),
    ("src/syscheckd/run_check.c\nstart_daemon", "src/syscheckd/run_check.c\nfim_send_msg"),
]

rootcheckd_nodes = [
    {"module": "rootcheckd", "src": "src/rootcheck/run_rk_check.c", "func": "notify_rk", "medium": "DEFAULTQUEUE", "action": "SEND"},
]
rootcheckd_calls = [
]

agentlessd_nodes = [
    {"module": "agentlessd", "src": "src/agentlessd/lessdcom.c", "func": "lessdcom_main", "medium": "LESSD_LOCAL_SOCK", "action": "RECV"},
    {"module": "agentlessd", "src": "src/agentlessd/agentlessd.c", "func": "send_intcheck_msg", "medium": "DEFAULTQUEUE", "action": "SEND"},
    {"module": "agentlessd", "src": "src/agentlessd/agentlessd.c", "func": "send_log_msg", "medium": "DEFAULTQUEUE", "action": "SEND"},
    {"module": "agentlessd", "src": "src/agentlessd/agentlessd.c", "func": "gen_diff_alert", "medium": "DEFAULTQUEUE", "action": "SEND"},
]
agentlessd_calls = [
    ("src/agentlessd/agentlessd.c\nAgentlessd", "src/agentlessd/agentlessd.c\nrun_periodic_cmd"),
    ("src/agentlessd/agentlessd.c\nrun_periodic_cmd", "src/agentlessd/agentlessd.c\nsend_intcheck_msg"),
    ("src/agentlessd/agentlessd.c\nrun_periodic_cmd", "src/agentlessd/agentlessd.c\nsend_log_msg"),
    ("src/agentlessd/agentlessd.c\nrun_periodic_cmd", "src/agentlessd/agentlessd.c\nsend_intcheck_msg"),
]

analysisd_nodes = [
    {"module": "analysisd", "src": "src/analysisd/analysisd.c", "func": "ad_input_main", "medium": "DEFAULTQUEUE", "action": "RECV"},
]
analysisd_calls = [
]

all_nodes = external_nodes + remoted_nodes + syscheckd_nodes + rootcheckd_nodes + agentlessd_nodes + analysisd_nodes
all_calls = remoted_calls + syscheckd_calls + rootcheckd_calls + agentlessd_calls + analysisd_calls

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

