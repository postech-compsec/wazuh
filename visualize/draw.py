import networkx as nx
from collections import defaultdict
import plotly.graph_objects as go
import json
from hashlib import sha256
import math

node_data = json.load(open("data/nodes.json"))
call_data = json.load(open("data/calls.json"))

G = nx.DiGraph()
nodes = list(
    set(
        [label for n in node_data if (label := f"{n['code']}<br>{n['func']}") != "<br>"]
        + [f"{n['src_code']}<br>{n['src_func']}" for n in call_data]
        + [f"{n['dst_code']}<br>{n['dst_func']}" for n in call_data]
    )
)
mediums = list(set([n["medium"] for n in node_data if "UDP" not in n["medium"]]))
udp = list(set([n["medium"] for n in node_data if "UDP" in n["medium"]]))

for node in node_data:
    G.add_node(
        f"{node['code']}<br>{node['func']}",
        module=node["module"],
        code=node["code"],
        func=node["func"],
        medium=node["medium"],
    )

for node in call_data:
    G.add_node(
        f"{node['src_code']}<br>{node['src_func']}",
        module=node["src_module"],
        code=node["src_code"],
        func=node["src_func"],
        medium=None,
    )
    G.add_node(
        f"{node['dst_code']}<br>{node['dst_func']}",
        module=node["dst_module"],
        code=node["dst_code"],
        func=node["dst_func"],
        medium=None,
    )

for m in mediums:
    G.add_node(m, module="MEDIUM", medium=m)

for u in udp:
    G.add_node(u, module="UDP", medium=u)

# Via Mediums: add middle nodes for mediums
edge_mediums = []

edge_mediums += [
    (f"{n['code']}<br>{n['func']}", n["medium"])
    for n in node_data
    if n["action"] == "SEND"
]
edge_mediums += [
    (n["medium"], f"{n['code']}<br>{n['func']}")
    for n in node_data
    if n["action"] == "RECV"
]

edge_calls = [
    (f"{n['src_code']}<br>{n['src_func']}", f"{n['dst_code']}<br>{n['dst_func']}")
    for n in call_data
]

# Function Calls
G.add_edges_from(edge_mediums)
G.add_edges_from(edge_calls)

position = nx.kamada_kawai_layout(G)

module_list = list(set([G.nodes[n]["module"] for n in nodes]))
medium_list = list(set([G.nodes[n]["medium"] for n in nodes]))

W_factor = 3
H_factor = 5
inner_factor = 0.5
original_vct_factor = 3

for node in G.nodes():
    if G.nodes[node]["module"] == "MEDIUM":
        position[node] = (
            W_factor
            * inner_factor
            * math.cos(
                mediums.index(G.nodes[node]["medium"]) * 2 * math.pi / len(mediums)
            ),
            H_factor
            * inner_factor
            * math.sin(
                mediums.index(G.nodes[node]["medium"]) * 2 * math.pi / len(mediums)
            ),
        )
    elif G.nodes[node]["module"] == "UDP":
        position[node] = (
            W_factor + udp.index(G.nodes[node]["medium"]) * inner_factor,
            H_factor,
        )
    else:
        position[node] = (
            position[node][0] * original_vct_factor
            + W_factor
            * math.cos(
                module_list.index(G.nodes[node]["module"])
                * 2
                * math.pi
                / len(module_list)
            ),
            position[node][1] * original_vct_factor
            + H_factor
            * math.sin(
                module_list.index(G.nodes[node]["module"])
                * 2
                * math.pi
                / len(module_list)
            ),
        )


traces = []
for module in module_list:
    traces.append(
        go.Scatter(
            name=module,
            x=[position[n][0] for n in nodes if G.nodes[n]["module"] == module],
            y=[position[n][1] for n in nodes if G.nodes[n]["module"] == module],
            mode="markers",
            text=[n for n in nodes if G.nodes[n]["module"] == module],
            # textposition="top center",
            marker={
                "symbol": "square",
                "size": 20,
                "color": f"#{sha256(module.encode()).hexdigest()[:6]}",
            },
            hoverinfo="text",
            hoverlabel={
                "font_size": 10,
                "font_family": "monospace",
            },
        )
    )


medium_trace = go.Scatter(
    name="Mediums",
    x=[position[n][0] for n in mediums],
    y=[position[n][1] for n in mediums],
    mode="markers+text",
    text=mediums,
    textposition="top center",
    marker={
        "symbol": "circle",
        "size": 20,
        "color": "pink",
        "line": {"width": 3, "color": "violet"},
    },
    hoverinfo="text",
    hoverlabel={
        "font_size": 10,
        "font_family": "monospace",
    },
)

udp_trace = go.Scatter(
    name="UDP",
    x=[position[n][0] for n in udp],
    y=[position[n][1] for n in udp],
    mode="markers+text",
    text=udp,
    textposition="top center",
    marker={
        "symbol": "circle",
        "size": 20,
        "color": "skyblue",
        "line": {"width": 3, "color": "teal"},
    },
    hoverinfo="text",
    hoverlabel={
        "font_size": 10,
        "font_family": "monospace",
    },
)
annotations = []
for src, dst in G.edges():
    src_x, src_y = position[src]
    dst_x, dst_y = position[dst]
    # Via Medium
    if src in mediums:
        annotations.append(
            {
                "ax": src_x,
                "ay": src_y,
                "x": dst_x,
                "y": dst_y,
                "xref": "x",
                "yref": "y",
                "axref": "x",
                "ayref": "y",
                "showarrow": True,
                "arrowhead": 2,
                "arrowsize": 2,
                "arrowwidth": 1,
                "arrowcolor": "blue",
            }
        )
    elif dst in mediums or dst in udp:
        annotations.append(
            {
                "ax": src_x,
                "ay": src_y,
                "x": dst_x,
                "y": dst_y,
                "xref": "x",
                "yref": "y",
                "axref": "x",
                "ayref": "y",
                "showarrow": True,
                "arrowhead": 2,
                "arrowsize": 2,
                "arrowwidth": 1,
                "arrowcolor": "blue",
            }
        )
    # Function Calls
    else:
        annotations.append(
            {
                "ax": src_x,
                "ay": src_y,
                "x": dst_x,
                "y": dst_y,
                "xref": "x",
                "yref": "y",
                "axref": "x",
                "ayref": "y",
                "showarrow": True,
                "arrowhead": 2,
                "arrowsize": 2,
                "arrowwidth": 1,
                "arrowcolor": "red",
            }
        )

fig = go.Figure(data=traces + [medium_trace, udp_trace])
fig.update_layout(
    title="Wazuh Dataflow Diagram",
    annotations=annotations,
    xaxis={"showgrid": False, "zeroline": False, "showticklabels": False},
    yaxis={"showgrid": False, "zeroline": False, "showticklabels": False},
    plot_bgcolor="white",
    margin={"l": 20, "r": 20, "t": 40, "b": 20},
)

# write out an interactive HTML you can open in your browser
fig.write_html("wazuh_dataflow.html", include_plotlyjs="cdn")
