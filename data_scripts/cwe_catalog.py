import zipfile
import requests
import json
from pathlib import Path

import networkx as nx
import xmltodict

__all__ = []

data_cache_dir = Path(__file__).parent / "cache"
data_cache_dir.mkdir(parents=False, exist_ok=True)

cwe_data_url = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
zip_file_path = data_cache_dir / "cwec_latest.xml.zip"
cwe_xml_path = data_cache_dir / "cwec_latest.xml"


def download_cwe_catalog() -> None:
    print(f"Downloading and extracting from: {cwe_data_url}")
    response = requests.get(cwe_data_url, stream=True)
    response.raise_for_status()

    with open(zip_file_path, 'wb') as file:
        for chunk in response.iter_content(chunk_size=8192):
            file.write(chunk)

    with zipfile.ZipFile(zip_file_path, 'r') as zip_ref:
        extracted_path = zip_ref.extract(zip_ref.infolist()[0].filename, data_cache_dir)
        extracted_path = Path(extracted_path)
        extracted_path.rename(cwe_xml_path)

    print('CWE catalog has been saved to', cwe_xml_path)


def get_cwe_list() -> dict:
    if not cwe_xml_path.exists():
        download_cwe_catalog()
    
    with open(cwe_xml_path, 'r', encoding='utf-8') as file:
        root_obj = xmltodict.parse(file.read())
    
    cwe_version = root_obj['Weakness_Catalog']['@Version']
    cwe_date = root_obj['Weakness_Catalog']['@Date']
    print(f'Commmon Weakness Enumeration Catalog ({cwe_version} {cwe_date})')
    
    weaknesses = root_obj['Weakness_Catalog']['Weaknesses']['Weakness']
    categories = root_obj['Weakness_Catalog']['Categories']['Category']
    views = root_obj['Weakness_Catalog']['Views']['View']
    print(f"Number of CWE weaknesses: {len(weaknesses)}")
    print(f"Number of CWE categories: {len(categories)}")
    print(f"Number of CWE views: {len(views)}")

    # build CWE metadata dict
    cwe_metadata = {}

    for weakness in weaknesses:
        weakness_id = 'CWE-' + weakness['@ID']
        weakness_name = weakness['@Name']
        abstraction = weakness['@Abstraction']
        description = weakness['Description']
        vulnerability_mapping = weakness['Mapping_Notes']['Usage']

        try:
            rw = weakness['Related_Weaknesses']['Related_Weakness']
            rw = rw if isinstance(rw, list) else [rw,]
            related_weaknesses = [
                {k[1:]: v for k, v in r.items()} for r in rw
            ]
        except KeyError:
            related_weaknesses = []

        cwe_metadata[weakness_id] = {
            'cwe_entry_type': 'weakness',
            'name': weakness_name,
            'abstraction': abstraction,
            'description': description,
            'vulnerability_mapping': vulnerability_mapping,
            'related_weaknesses': related_weaknesses,
        }
    
    for category in categories:
        category_id = 'CWE-' + category['@ID']
        category_name = category['@Name']
        category_summary = category['Summary']
        if category.get('Relationships'):
            m = category['Relationships']['Has_Member']
            m = m if isinstance(m, list) else [m,]
            members = [
                {k[1:]: v for k, v in r.items()} for r in m
            ]
        else:
            members = []
        cwe_metadata[category_id] = {
            'cwe_entry_type': 'category',
            'name': category_name,
            'description': category_summary,
            'vulnerability_mapping': 'Prohibited',
            'members': members,
        }
        
    for view in views:
        view_id = 'CWE-' + view['@ID']
        view_name = view['@Name']
        view_description = view['Objective']
        if view.get('Members'):
            m = view['Members']['Has_Member']
            m = m if isinstance(m, list) else [m,]
            members = [
                {k[1:]: v for k, v in r.items()} for r in m
            ]
        else:
            members = []
        cwe_metadata[view_id] = {
            'cwe_entry_type': 'view',
            'name': view_name,
            'description': view_description,
            'vulnerability_mapping': 'Prohibited',
            'members': members,
        }

    print('Number of CWE IDs:', len(cwe_metadata))
    
    return cwe_metadata


def generate_graph_data(cwe_metadata):
    edges = []
    for cwe_id, metadata in cwe_metadata.items():
        if rws := metadata.get('related_weaknesses'):
            for rw_dict in rws:
                if (rw_dict['Nature'] == 'ChildOf' and 
                    rw_dict.get('View_ID') == '1000' and 
                    rw_dict.get('Ordinal') == 'Primary'):
                    edges.append((rw_dict['CWE_ID'], cwe_id[4:], ))
    
    abstractions = ( "Compound", "Pillar", "Class", "Base", "Variant",)
    # hard-coded for now
    top_cwe_ids = ['CWE-125', 'CWE-119', 'CWE-787', 'CWE-476', 'CWE-Other', 'CWE-416', 'CWE-20', 'CWE-190', 'CWE-200', 'CWE-399', 'CWE-120', 'CWE-401', 'CWE-264', 'CWE-362', 'CWE-189', 'CWE-772', 'CWE-835', 'CWE-617', 'CWE-369', 'CWE-415', 'CWE-400', 'CWE-122', 'CWE-770', 'CWE-22', 'CWE-908', 'CWE-284', 'CWE-674', 'CWE-254', 'CWE-295', 'CWE-59', 'CWE-193', 'CWE-287', 'CWE-269', 'CWE-834', 'CWE-667', 'CWE-310', 'CWE-17', 'CWE-754', 'CWE-843', 'CWE-755', 'CWE-909', 'CWE-404', 'CWE-665', 'CWE-191', 'CWE-79', 'CWE-252', 'CWE-78', 'CWE-681', 'CWE-89', 'CWE-704']
    top_cwe_ids = set(top_cwe_ids)

    graph = nx.DiGraph(edges)

    def export_data_of_root(target_root_cwe_node = '664') -> dict:
        if parents := graph.in_edges([target_root_cwe_node]):
            raise ValueError(f"Node {target_root_cwe_node} has edge {parents}")

        visible_nodes = []
        for node in graph.nodes:
            if nx.has_path(graph, target_root_cwe_node, node):
                visible_nodes.append(node)
        print(f'tree root {target_root_cwe_node} has nodes: {len(visible_nodes)}')

        # 1 export nodes
        export_nodes = []
        for cwe_node in visible_nodes:
            depth = nx.shortest_path_length(graph, target_root_cwe_node, cwe_node)
            category = cwe_metadata[f"CWE-{cwe_node}"]['abstraction']
            style = {
                # "borderColor": usage_color_map[cwe_metadata[f"CWE-{cwe_node}"]['vulnerability_mapping']],
                "borderWidth": 0,
            }
            if f"CWE-{cwe_node}" in top_cwe_ids:
                style['borderColor'] = '#9B30FF'
                style['borderWidth'] = 2
                style["opacity"] = 1.0
            else:
                style["opacity"] = 1.0
            export_nodes.append({
                "name": f"CWE-{cwe_node}",
                "value": cwe_metadata[f"CWE-{cwe_node}"]['vulnerability_mapping'],
                "symbolSize": 15 - depth * 2 if cwe_node != target_root_cwe_node else 15 * 2,
                "category": category,
                "itemStyle": style,
            })

        # 2 export edges
        export_links = []
        valid_set = set(visible_nodes)
        for edge in edges:
            if edge[0] in valid_set and edge[1] in valid_set:
                export_links.append({
                    "source": f"CWE-{edge[0]}",
                    "target": f"CWE-{edge[1]}",
                    "value": 1,
                    "symbol": ["none", "arrow"],
                    "symbolSize": 5,
                })
        print(f'tree root {target_root_cwe_node} has edges: {len(export_links)}')

        export_categories = [
            {"name": c} for c in abstractions
        ]

        return {
            "nodes": export_nodes, 
            "links": export_links, 
            "categories": export_categories, 
            "legends": abstractions
        }
    
    all_graphs = {}
    for node in graph.nodes:
        try:
            obj = export_data_of_root(node)
        except ValueError:
            continue
        all_graphs[node] = obj
    
    return all_graphs


def main():
    cwes = get_cwe_list()
    target_dir = Path(__file__).parent.parent / 'public'
    with open(target_dir / 'cwe_metadata.json', 'w') as json_file:
        json.dump(cwes, json_file, indent=2)
    graph_data = generate_graph_data(cwes)
    with open(target_dir / 'graph_data.json', 'w') as json_file:
        json.dump(graph_data, json_file, indent=2)


if __name__ == '__main__':
    main()
