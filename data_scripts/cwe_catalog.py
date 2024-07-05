
from typing import Any
import zipfile
import json
from collections import OrderedDict
from pathlib import Path

import requests
import networkx as nx
import xmltodict


class CWECatalog:
    data_cache_dir: Path = Path(__file__).parent / "cache"
    cwe_data_url = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
    cwe_xml_path: Path = data_cache_dir / "cwec_latest.xml"

    def _download_cwe(self) -> None:
        self.data_cache_dir.mkdir(parents=False, exist_ok=True)
        zip_file_path = self.data_cache_dir / "cwec_latest.xml.zip"
        print(f"Downloading and extracting from: {self.cwe_data_url}")
        response = requests.get(self.cwe_data_url, stream=True)
        response.raise_for_status()
        with open(zip_file_path, 'wb') as file:
            for chunk in response.iter_content(chunk_size=8192):
                file.write(chunk)
        with zipfile.ZipFile(zip_file_path, 'r') as zip_ref:
            extracted_path = zip_ref.extract(zip_ref.infolist()[0].filename, self.data_cache_dir)
            extracted_path = Path(extracted_path)
            extracted_path.rename(self.cwe_xml_path)
        print(f'CWE catalog XML has been saved to {self.cwe_xml_path}')
    
    def _load_cwe_xml(self) -> OrderedDict[str, Any]:
        if not self.cwe_xml_path.exists():
            self._download_cwe()
        
        with open(self.cwe_xml_path, 'r', encoding='utf-8') as file:
            root_obj = xmltodict.parse(file.read())
        print(f'Loaded CWE catalog data from {self.cwe_xml_path}')
        return root_obj
    
    def __init__(self) -> None:
        self._root_dict = self._load_cwe_xml()
        self._cwe_info = self.get_simplified_cwe_entry_info()
        
        # tree structure, based on CWE-1000 Research Concepts
        self.tree = self._build_tree_of(view_id='1000')
        # Each node has exactly one parent node, so we use a dict to store this relationship.
        self.parent_map: dict[str, str] = { e[1]:e[0] for e in self.tree.edges }
        self.graph = self._build_graph(view_id='1000')
    
    def __getitem__(self, index: str | int) -> dict[str, Any]:
        if isinstance(index, str):
            if index.startswith('CWE-'):
                cwe_id = index
            elif index.isnumeric():
                cwe_id = f'CWE-{index}'
            else:
                cwe_id = ''
        elif isinstance(index, int):
            cwe_id = 'CWE-' + str(index)
        else:
            cwe_id = ''
        
        try:
            return self._cwe_info[cwe_id]
        except KeyError:
            raise KeyError(f'CWE ID not found: {index}')
    
    @property
    def weaknesses(self) -> list[OrderedDict]:
        return self._root_dict['Weakness_Catalog']['Weaknesses']['Weakness']
    
    @property
    def categories(self) -> list[OrderedDict]:
        return self._root_dict['Weakness_Catalog']['Categories']['Category']
    
    @property
    def views(self) -> list[OrderedDict]:
        return self._root_dict['Weakness_Catalog']['Views']['View']
    
    @property
    def all_cwe_ids(self):
        return self._cwe_info.keys()

    def show_cwe_basic_info(self) -> None:
        cwe_version = self._root_dict['Weakness_Catalog']['@Version']
        cwe_date = self._root_dict['Weakness_Catalog']['@Date']
        print(f'Commmon Weakness Enumeration Catalog ({cwe_version} {cwe_date})')
        print(f"Number of weaknesses: {len(self.weaknesses)}")
        print(f"Number of categories: {len(self.categories)}")
        print(f"Number of views: {len(self.views)}")
        print(f"Total entries: {len(self.all_cwe_ids)}")
    
    def get_simplified_cwe_entry_info(self) -> dict:
        cwe_metadata = {}

        for weakness in self.weaknesses:
            weakness_id = 'CWE-' + weakness['@ID']
            weakness_name = weakness['@Name']
            abstraction = weakness['@Abstraction']
            description = weakness['Description']
            vulnerability_mapping = weakness['Mapping_Notes']['Usage']
            if weakness.get('Related_Weaknesses'):
                rw = weakness['Related_Weaknesses']['Related_Weakness']
                rw = rw if isinstance(rw, list) else [rw,]
                related_weaknesses = [{k[1:]: v for k, v in r.items()} for r in rw]
            else:
                related_weaknesses = []
            cwe_metadata[weakness_id] = {
                'cwe_entry_type': 'weakness',
                'name': weakness_name,
                'abstraction': abstraction,
                'description': description,
                'vulnerability_mapping': vulnerability_mapping,
                'related_weaknesses': related_weaknesses,
            }
        
        for category in self.categories:
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
            
        for view in self.views:
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

        return cwe_metadata

    def _build_tree_of(self, view_id: str='1000') -> nx.DiGraph:
        edges = []
        for cwe_id in self.all_cwe_ids:
            if rws := self[cwe_id].get('related_weaknesses'):
                for rw_dict in rws:
                    if (rw_dict['Nature'] == 'ChildOf' and 
                        rw_dict.get('View_ID') == view_id and 
                        rw_dict.get('Ordinal') == 'Primary'):
                        edges.append(('CWE-' + rw_dict['CWE_ID'], cwe_id, dict()))
        for member in self[view_id]['members']:
            edges.append(('CWE-' + view_id, 'CWE-' + member['CWE_ID'], dict()))
        digraph = nx.DiGraph(edges)
        assert nx.is_arborescence(digraph), '? unexpected tree view ?!'
        return digraph

    def _build_graph(self, view_id: str='1000') -> nx.DiGraph:
        """heterogeneous graph of CWE entries
        
        edge type: the nature of a related weakness
        """
        edges = []

        def relationship_to_edge(_w: str, _rw: dict[str, str]) -> tuple[str, str, dict[str, str]]:
            # we want parent ---> child, so that: (parent) ---ParentOf--> (child)
            if _rw['Nature'] == 'ChildOf':
                return (
                    'CWE-' + _rw['CWE_ID'], # the parent
                    _w, # the child
                    {'nature': 'ParentOf', 'ordinal': _rw.get('Ordinal', '')},
                )
            else:
                return (
                    _w,
                    'CWE-' + _rw['CWE_ID'],
                    {'nature': _rw['Nature'], 'ordinal': _rw.get('Ordinal', '')},
                )

        for cwe_id in self.all_cwe_ids:
            if rws := self[cwe_id].get('related_weaknesses'):
                for rw_dict in rws:
                    if rw_dict.get('View_ID') == view_id and (rw_dict['Nature'] != 'ChildOf' or rw_dict.get('Ordinal') == 'Primary'):
                        edges.append(relationship_to_edge(cwe_id, rw_dict))

        for member in self[view_id]['members']:
            edges.append((
                'CWE-' + view_id,
                'CWE-' + member['CWE_ID'],
                {'nature': 'HasMember'}
            ))
        
        digraph = nx.DiGraph(edges)
        return digraph

    def find_path_on_tree(self, ancestor: str, descendant: str) -> list[str] | None:
        path = [descendant]
        current_node = descendant
        while current_node != ancestor:
            if current_node == 'CWE-1000': # reaches root node, fail
                return None
            current_node = self.parent_map[current_node]
            path.append(current_node)
        path.reverse()
        return path
    
    def get_pillar_weakness_ancestor(self, node: str) -> str | None:
        path_from_root = self.find_path_on_tree('CWE-1000', node)
        if path_from_root and len(path_from_root) > 1:
            assert self[path_from_root[1]]['abstraction'] == 'Pillar'
            return path_from_root[1]
        else:
            return None

    def find_lca_on_tree(self, node1: str, node2: str) -> str:
        return nx.lowest_common_ancestor(self.tree, node1, node2)


class GraphChartData(CWECatalog):
    abstractions = ("Compound", "Pillar", "Class", "Base", "Variant")
    # hard-coded for now
    top_cwe_ids = ['CWE-125', 'CWE-119', 'CWE-787', 'CWE-476', 'CWE-Other', 'CWE-416', 'CWE-20', 'CWE-190', 'CWE-200', 'CWE-399', 'CWE-120', 'CWE-401', 'CWE-264', 'CWE-362', 'CWE-189', 'CWE-772', 'CWE-835', 'CWE-617', 'CWE-369', 'CWE-415', 'CWE-400', 'CWE-122', 'CWE-770', 'CWE-22', 'CWE-908', 'CWE-284', 'CWE-674', 'CWE-254', 'CWE-295', 'CWE-59', 'CWE-193', 'CWE-287', 'CWE-269', 'CWE-834', 'CWE-667', 'CWE-310', 'CWE-17', 'CWE-754', 'CWE-843', 'CWE-755', 'CWE-909', 'CWE-404', 'CWE-665', 'CWE-191', 'CWE-79', 'CWE-252', 'CWE-78', 'CWE-681', 'CWE-89', 'CWE-704']
    top_cwe_ids = set(top_cwe_ids)

    def export_data(self, nodes: list[str], edges, root_node: str) -> dict:
        # 1 export nodes
        export_nodes = []
        export_links = []
        valid_node_set = set(nodes)
        for cwe_node in nodes:
            path_ = self.find_path_on_tree(root_node, cwe_node)
            if path_:
                depth = len(path_) - 1
            else:
                depth = 1
            category = self[cwe_node].get('abstraction', 'Pillar')
            style = {
                # "borderColor": usage_color_map[cwe_metadata[f"CWE-{cwe_node}"]['vulnerability_mapping']],
                "borderWidth": 0,
            }
            if cwe_node in self.top_cwe_ids:
                style['borderColor'] = '#9B30FF'
                style['borderWidth'] = 2
                style["opacity"] = 1.0
            else:
                style["opacity"] = 1.0
            export_nodes.append({
                "name": cwe_node,
                "value": self[cwe_node]['vulnerability_mapping'],
                "symbolSize": 15 - depth * 2 if cwe_node != root_node else 30,
                "category": category,
                "itemStyle": style,
            })
        for src, tgt, attr in edges.data('nature', default='ParentOf'):
            if src in valid_node_set and tgt in valid_node_set:
                export_links.append({
                    "source": src,
                    "target": tgt,
                    "value": attr,
                    "ignoreForceLayout": False if attr in ('ParentOf', 'HasMember') else True,
                    "lineStyle": {
                        "type": 'solid' if attr in ('ParentOf', 'HasMember') else 'dashed',
                    },
                    "symbol": ["none", "arrow"],
                    "symbolSize": 5,
                })
        
        print(f"root {root_node}: {len(export_nodes)} nodes, {len(export_links)}")
        return {
            "nodes": export_nodes, 
            "links": export_links, 
            "categories": [{"name": c} for c in self.abstractions], 
            "legends": self.abstractions
        }
    
    def generate_graph_data(self):
        all_graphs = {}

        # trees of pillar weaknesses
        for e in self.tree.out_edges(['CWE-1000']):
            root_node = e[1]
            visible_nodes = []
            for cwe_id in self.tree.nodes:
                if self.get_pillar_weakness_ancestor(cwe_id) == root_node:
                    visible_nodes.append(cwe_id)
            exported_graph = self.export_data(visible_nodes, self.tree.edges, root_node)
            graph_name = f"Tree of {root_node}: {self[root_node]['name']}"
            all_graphs[graph_name] = exported_graph
        
        # graph
        target_cwes = self.top_cwe_ids
        visible_nodes_on_graph = set()
        for target in target_cwes:
            if target not in self.graph.nodes:
                continue
            path = self.find_path_on_tree('CWE-1000', target)
            if path:
                visible_nodes_on_graph.update(path)
        exported_graph = self.export_data(visible_nodes_on_graph, self.graph.edges, 'CWE-1000')
        graph_name = f"Popular Weaknesses"
        all_graphs[graph_name] = exported_graph

        exported_graph = self.export_data(self.graph.nodes, self.graph.edges, 'CWE-1000')
        graph_name = f"All Weaknesses (could be very laggy)"
        all_graphs[graph_name] = exported_graph
        
        return all_graphs


def main():
    cwe_catalog = GraphChartData()
    cwe_catalog.show_cwe_basic_info()
    target_dir = Path(__file__).parent.parent / 'public'
    with open(target_dir / 'cwe_metadata.json', 'w') as json_file:
        json.dump(cwe_catalog._cwe_info, json_file, indent=0)
    graph_data = cwe_catalog.generate_graph_data()
    with open(target_dir / 'graph_data.json', 'w') as json_file:
        json.dump(graph_data, json_file, indent=0)


if __name__ == '__main__':
    main()
