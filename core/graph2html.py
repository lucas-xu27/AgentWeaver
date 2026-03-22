import json
import os
import argparse
from collections import defaultdict

def generate_html(json_path: str, output_path: str):
    print(f"Loading graph data from {json_path}...")
    with open(json_path, 'r', encoding='utf-8') as f:
        graph_data = json.load(f)

    nodes = graph_data.get('nodes', [])
    edges = graph_data.get('edges', [])
    print(f"Loaded {len(nodes)} nodes and {len(edges)} edges.")

    node_dict = {n['id']: n for n in nodes}
    
    # 构建出入边索引
    outgoing = defaultdict(list)
    incoming = defaultdict(list)
    for e in edges:
        outgoing[e['src']].append((e['rel'], e['dst']))
        incoming[e['dst']].append((e['rel'], e['src']))
        
    # 找到入口节点（没有入边的节点，通常是 User 节点）
    roots = [nid for nid in node_dict.keys() if not incoming[nid]]
    if not roots:
        roots = [n['id'] for n in nodes if n.get('type') in ['User', 'Task']]
        
    html = [
        "<!DOCTYPE html>",
        "<html lang='en'>",
        "<head>",
        "<meta charset='utf-8'>",
        "<meta name='viewport' content='width=device-width, initial-scale=1.0'>",
        "<title>OpenClaw Execution Graph</title>",
        "<link href='https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&family=Fira+Code:wght@400;500&display=swap' rel='stylesheet'>",
        "<style>",
        "body { font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif; background: #f3f4f6; color: #1f2937; padding: 2rem; margin: 0; line-height: 1.5; }",
        ".header { max-width: 1200px; margin: 0 auto 2rem auto; background: white; padding: 1.5rem 2rem; border-radius: 12px; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.05), 0 2px 4px -1px rgba(0, 0, 0, 0.03); display: flex; align-items: center; justify-content: space-between; }",
        ".header h1 { font-size: 1.5rem; font-weight: 600; margin: 0; color: #111827; display: flex; align-items: center; gap: 0.5rem; }",
        ".header p { margin: 0; font-size: 0.875rem; color: #6b7280; }",
        ".tree-container { max-width: 1200px; margin: 0 auto; }",
        ".node-container { margin-left: 2rem; border-left: 2px solid #e5e7eb; padding-left: 1.5rem; margin-top: 0.5rem; position: relative; }",
        "details { margin-bottom: 0.5rem; }",
        "details > summary { cursor: pointer; padding: 0.75rem 1rem; background: white; border: 1px solid #e5e7eb; border-radius: 8px; list-style: none; display: flex; align-items: center; box-shadow: 0 1px 2px rgba(0,0,0,0.02); transition: all 0.2s ease; user-select: none; }",
        "details > summary::-webkit-details-marker { display: none; }",
        "details > summary:hover { border-color: #d1d5db; box-shadow: 0 2px 4px rgba(0,0,0,0.04); transform: translateY(-1px); }",
        "details[open] > summary { border-radius: 8px 8px 0 0; border-bottom: 1px solid transparent; background: #f8fafc; font-weight: 500; }",
        ".summary-content { display: flex; align-items: center; gap: 0.75rem; flex: 1; overflow: hidden; }",
        ".chevron { width: 16px; height: 16px; transition: transform 0.2s; color: #9ca3af; flex-shrink: 0; }",
        "details[open] > summary .chevron { transform: rotate(90deg); color: #4b5563; }",
        ".content-box { background: white; border: 1px solid #e5e7eb; border-top: none; border-radius: 0 0 8px 8px; padding: 1.25rem; font-family: 'Fira Code', monospace; font-size: 0.8125rem; overflow-x: auto; white-space: pre-wrap; word-wrap: break-word; max-height: 400px; overflow-y: auto; color: #374151; box-shadow: 0 1px 2px rgba(0,0,0,0.02) inset; }",
        "/* Scrollbar styling */",
        ".content-box::-webkit-scrollbar { width: 6px; height: 6px; }",
        ".content-box::-webkit-scrollbar-track { background: #f1f1f1; border-radius: 4px; }",
        ".content-box::-webkit-scrollbar-thumb { background: #d1d5db; border-radius: 4px; }",
        ".content-box::-webkit-scrollbar-thumb:hover { background: #9ca3af; }",
        ".tag { font-size: 0.7rem; font-weight: 600; font-family: 'Inter', sans-serif; text-transform: uppercase; letter-spacing: 0.05em; color: white; padding: 0.25rem 0.6rem; border-radius: 9999px; display: inline-flex; align-items: center; gap: 0.25rem; flex-shrink: 0; }",
        ".tag-User { background: linear-gradient(135deg, #ef4444 0%, #dc2626 100%); box-shadow: 0 2px 4px rgba(239, 68, 68, 0.2); }",
        ".tag-Task { background: linear-gradient(135deg, #f59e0b 0%, #d97706 100%); box-shadow: 0 2px 4px rgba(245, 158, 11, 0.2); }",
        ".tag-Tool { background: linear-gradient(135deg, #10b981 0%, #059669 100%); box-shadow: 0 2px 4px rgba(16, 185, 129, 0.2); }",
        ".tag-Data { background: linear-gradient(135deg, #8b5cf6 0%, #6d28d9 100%); box-shadow: 0 2px 4px rgba(139, 92, 246, 0.2); }",
        ".tag-Process { background: linear-gradient(135deg, #3b82f6 0%, #2563eb 100%); box-shadow: 0 2px 4px rgba(59, 130, 246, 0.2); }",
        ".tag-File { background: white; color: #1f2937; border: 1px solid #d1d5db; box-shadow: 0 1px 2px rgba(0,0,0,0.05); }",
        ".tag-Network { background: linear-gradient(135deg, #f97316 0%, #ea580c 100%); box-shadow: 0 2px 4px rgba(249, 115, 22, 0.2); }",
        ".node-title-text { font-size: 0.95rem; font-weight: 500; color: #111827; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }",
        ".node-subtitle { font-size: 0.8rem; color: #6b7280; font-weight: 400; margin-left: 0.5rem; flex-shrink: 0; }",
        ".edge-label { font-size: 0.75rem; color: #6b7280; margin: 0.5rem 0 0.25rem 0; font-weight: 500; display: flex; align-items: center; gap: 0.5rem; letter-spacing: 0.025em; text-transform: uppercase; }",
        ".edge-label::before { content: ''; display: block; width: 12px; height: 1px; background: #d1d5db; }",
        ".error-badge { display: inline-flex; align-items: center; justify-content: center; background: #fee2e2; color: #dc2626; font-size: 0.7rem; font-weight: 600; padding: 0.1rem 0.4rem; border-radius: 4px; margin-left: 0.5rem; border: 1px solid #fecaca; }",
        ".attr-row { display: flex; margin-bottom: 0.35rem; border-bottom: 1px dashed #f3f4f6; padding-bottom: 0.35rem; }",
        ".attr-row:last-child { border-bottom: none; margin-bottom: 0; padding-bottom: 0; }",
        ".attr-key { color: #6b7280; font-weight: 500; width: 140px; flex-shrink: 0; user-select: none; }",
        ".attr-val { color: #111827; flex: 1; word-break: break-all; }",
        ".attr-val-json { color: #047857; }",
        "@media (max-width: 768px) { .attr-row { flex-direction: column; gap: 0.25rem; } .attr-key { width: 100%; } .node-container { margin-left: 1rem; padding-left: 0.75rem; } }",
        "</style>",
        "</head>",
        "<body>",
        "<div class='header'>",
        "  <div>",
        "    <h1>",
        "      <svg width='24' height='24' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'><path d='M18 3a3 3 0 0 0-3 3v12a3 3 0 0 0 3 3 3 3 0 0 0 3-3 3 3 0 0 0-3-3H6a3 3 0 0 0-3 3 3 3 0 0 0 3 3 3 3 0 0 0 3-3V6a3 3 0 0 0-3-3 3 3 0 0 0-3 3h12a3 3 0 0 0 3-3 3 3 0 0 0-3-3z'></path></svg>",
        "      OpenClaw Execution Graph",
        "    </h1>",
        "    <p>Static Tree View · Optimized for Review</p>",
        "  </div>",
        "  <div style='font-size: 0.85rem; color: #6b7280; text-align: right;'>",
        f"    Nodes: <b>{len(nodes)}</b><br>Edges: <b>{len(edges)}</b>",
        "  </div>",
        "</div>",
        "<div class='tree-container'>"
    ]
    
    visited = set()

    def render_node(node_id):
        if node_id in visited:
            return f"<div class='edge-label' style='color:#9ca3af;'>&nbsp; Already referenced: {node_id}</div>"
            
        visited.add(node_id)
        node = node_dict.get(node_id)
        if not node:
            return f"<div class='node-container' style='color:#ef4444;'>Unknown Node: {node_id}</div>"
            
        node_type = node.get('type', 'Unknown')
        
        # Build Title
        title_tag = f"<span class='tag tag-{node_type}'>{node_type}</span>"
        title_text = ""
        subtitle = ""
        error_badge = " <span class='error-badge'>ERROR</span>" if node.get('is_error') else ""

        if node_type == 'User': 
            title_text = node.get('name', node_id)
        elif node_type == 'Task': 
            title_text = node.get('label', node_id)
            subtitle = f"({node.get('task_type', '')})"
        elif node_type == 'Tool': 
            title_text = node.get('name', node_id)
        elif node_type == 'Data': 
            title_text = f"Result of {node.get('tool_name', 'tool')}"
        elif node_type == 'Process': 
            title_text = node.get('comm', node_id)
            subtitle = f"PID: {node.get('pid', 'N/A')}"
        elif node_type == 'File': 
            title_text = node.get('basename', node_id)
        elif node_type == 'Network': 
            title_text = node.get('host', node_id)
        else:
            title_text = node_id
            
        # Chevron icon SVG
        chevron = "<svg class='chevron' viewBox='0 0 20 20' fill='currentColor'><path fill-rule='evenodd' d='M7.293 14.707a1 1 0 010-1.414L10.586 10 7.293 6.707a1 1 0 011.414-1.414l4 4a1 1 0 010 1.414l-4 4a1 1 0 01-1.414 0z' clip-rule='evenodd'/></svg>"
        
        open_attr = " open" if node_type in ['User', 'Task', 'Tool'] else ""
        
        out = [
            f"<details{open_attr}>",
            f"  <summary>",
            f"    {chevron}",
            f"    <div class='summary-content'>",
            f"      {title_tag}",
            f"      <span class='node-title-text'>{title_text}{error_badge}</span>",
            f"      <span class='node-subtitle'>{subtitle}</span>",
            f"    </div>",
            f"  </summary>",
            f"  <div class='content-box'>"
        ]
        
        # Render attributes
        for k, v in node.items():
            if k in ['id', 'type']: continue
            if k in ['arguments', 'content', 'input_task', 'received_data_returns', 'received_task_returns'] or isinstance(v, (dict, list)):
                formatted_json = json.dumps(v, indent=2, ensure_ascii=False) if not isinstance(v, str) else v
                out.append(f"<div class='attr-row'><span class='attr-key'>{k}</span><span class='attr-val attr-val-json'>{formatted_json}</span></div>")
            else:
                out.append(f"<div class='attr-row'><span class='attr-key'>{k}</span><span class='attr-val'>{v}</span></div>")
        
        out.append("  </div>") # close content-box
        
        # Render children
        children = outgoing.get(node_id, [])
        children.sort(key=lambda x: x[0]) # simple sort by relation string
        
        if children:
            out.append("  <div class='node-container'>")
            for rel, tgt in children:
                # Add a subtle dot before the edge label
                out.append(f"<div class='edge-label'><span style='display:inline-block;width:6px;height:6px;border-radius:50%;background:#9ca3af;margin-right:2px;'></span>{rel}</div>")
                out.append(render_node(tgt))
            out.append("  </div>")
            
        out.append("</details>")
        return "\n".join(out)

    for root_id in roots:
        if node_dict.get(root_id, {}).get('type') == 'User':
            html.append(render_node(root_id))
            
    for n in nodes:
        if n.get('type') == 'Task' and n['id'] not in visited:
            html.append(render_node(n['id']))

    html.append("</div>") # close tree-container
    html.append("</body></html>")

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write("\n".join(html))
    print(f"Modern stylized HTML tree successfully generated at: {output_path}")

def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(script_dir)
    default_json = os.path.join(project_root, "logs", "graph.json")
    default_html = os.path.join(project_root, "logs", "graph.html")
    parser = argparse.ArgumentParser(description="Convert graph.json into a beautiful static HTML tree view")
    parser.add_argument("--input", default=default_json, help="Path to graph.json")
    parser.add_argument("--output", default=default_html, help="Path to the output HTML file")
    args = parser.parse_args()
    if not os.path.exists(args.input):
        print(f"Error: Input file {args.input} does not exist.")
        return
    generate_html(args.input, args.output)

if __name__ == "__main__":
    main()
