"""
trace.py
========
从检测出的风险节点触发，回溯至攻击源头 (User 或 Data节点)。
读取通过 detect.py 产出的 detection_results.json 作为输入，输出溯源路径。
"""

from __future__ import annotations

import argparse
import json
import os
from typing import Dict, List
from datetime import datetime

import numpy as np
import jieba
from sentence_transformers import SentenceTransformer, util
from rank_bm25 import BM25Okapi

# 解决直接运行和作为模块运行时的模块导入路径差异
try:
    from core.detect import GraphAnalyzer, _node_text
except ImportError:
    from detect import GraphAnalyzer, _node_text


# ─────────────────────────────────────────────────────────────────────────────
# 文本工具函数 (Chunked Hybrid Similarity)
# ─────────────────────────────────────────────────────────────────────────────

def chunk_text(text: str, chunk_size: int = 200, overlap: int = 50) -> List[str]:
    """滑窗切分长文本为短片段。"""
    if not text:
        return [""]
    text_len = len(text)
    if text_len <= chunk_size:
        return [text]
    chunks = []
    start = 0
    while start < text_len:
        end = min(start + chunk_size, text_len)
        chunks.append(text[start:end])
        if end == text_len:
            break
        start += (chunk_size - overlap)
    return chunks


def normalize_scores(scores: np.ndarray) -> np.ndarray:
    """最大最小归一化。"""
    if len(scores) == 0:
        return scores
    if scores.max() == scores.min():
        return np.ones_like(scores) * 0.5
    return (scores - scores.min()) / (scores.max() - scores.min())


def calculate_chunked_hybrid_similarity(
    query: str,
    comparison_texts: List[str],
    model: SentenceTransformer,
    alpha: float = 0.5,
) -> List[Dict]:
    """
    Chunking + Max Pooling 混合相似度计算。
    对每篇文档切片，取 Dense (BGE-M3) + BM25 混合打分，
    以最高分 Chunk 代表整篇文档。
    """
    all_chunks = []
    chunk_to_doc_idx = []

    for doc_idx, doc_text in enumerate(comparison_texts):
        chunks = chunk_text(doc_text, chunk_size=200, overlap=50)
        for c in chunks:
            all_chunks.append(c)
            chunk_to_doc_idx.append(doc_idx)

    query_embedding = model.encode(query, convert_to_tensor=True)
    chunk_embeddings = model.encode(all_chunks, convert_to_tensor=True)
    cosine_scores = util.cos_sim(query_embedding, chunk_embeddings)[0].cpu().numpy()
    norm_cosine_scores = normalize_scores(cosine_scores)

    tokenized_corpus = [list(jieba.cut(c)) for c in all_chunks]
    bm25 = BM25Okapi(tokenized_corpus)
    tokenized_query = list(jieba.cut(query))
    bm25_scores = np.array(bm25.get_scores(tokenized_query))
    norm_bm25_scores = normalize_scores(bm25_scores)

    chunk_hybrid_scores = (alpha * norm_cosine_scores) + ((1 - alpha) * norm_bm25_scores)

    results = []
    for doc_idx, doc_text in enumerate(comparison_texts):
        child_indices = [i for i, mapped_id in enumerate(chunk_to_doc_idx) if mapped_id == doc_idx]
        best_chunk_idx = max(child_indices, key=lambda i: chunk_hybrid_scores[i])
        results.append({
            "doc_idx": doc_idx,
            "text": doc_text,
            "best_chunk": all_chunks[best_chunk_idx],
            "hybrid_score": float(chunk_hybrid_scores[best_chunk_idx]),
            "dense_score": float(cosine_scores[best_chunk_idx]),
            "bm25_score": float(bm25_scores[best_chunk_idx]),
            "norm_dense": float(norm_cosine_scores[best_chunk_idx]),
            "norm_bm25": float(norm_bm25_scores[best_chunk_idx]),
        })

    results.sort(key=lambda x: x["hybrid_score"], reverse=True)
    return results


# ─────────────────────────────────────────────────────────────────────────────
# 攻击路径回溯
# ─────────────────────────────────────────────────────────────────────────────

def trace_attack_path(
    analyzer: GraphAnalyzer,
    risk_node_id: str,
    model: SentenceTransformer,
    alpha: float = 0.5,
    max_depth: int = 20,
) -> List[dict]:
    """
    从风险节点出发，利用 Chunked Hybrid Similarity 做语义引导的反向溯源。
    递归追踪直到到达 User 节点或 Data 节点或没有入边（visited 集合防止环路）。
    """
    print(f"\n  🔙 从 {risk_node_id} 开始反向溯源...")

    risk_node = analyzer.get_node(risk_node_id)
    if not risk_node:
        print(f"    节点 {risk_node_id} 不存在")
        return []

    query_text = _node_text(risk_node)
    path = [{
        "node_id": risk_node_id,
        "node_type": risk_node.get("type", ""),
        "text_preview": query_text[:200],
        "similarity": 1.0,
        "edge_rel": "ORIGIN",
    }]

    visited = {risk_node_id}
    current_id = risk_node_id

    for step in range(max_depth):
        in_edges = analyzer.get_in_edges(current_id)
        if not in_edges:
            print(f"    步骤 {step + 1}: 无入边，溯源终止")
            break

        # 获取所有源节点（去重、排除已访问）
        candidate_nodes = []
        candidate_texts = []
        candidate_edges = []
        for edge in in_edges:
            src_id = edge["src"]
            if src_id in visited:
                continue
            src_node = analyzer.get_node(src_id)
            if not src_node:
                continue
            node_text = _node_text(src_node)
            candidate_nodes.append(src_node)
            candidate_texts.append(node_text)
            candidate_edges.append(edge)

        if not candidate_nodes:
            print(f"    步骤 {step + 1}: 所有源节点已访问，溯源终止")
            break

        # 使用混合相似度找到与风险描述最相关的源节点
        sim_results = calculate_chunked_hybrid_similarity(
            query=query_text,
            comparison_texts=candidate_texts,
            model=model,
            alpha=alpha,
        )

        # 找到原始索引中得分最高的
        best_result = sim_results[0]
        best_doc_idx = best_result["doc_idx"]
        best_node = candidate_nodes[best_doc_idx]
        best_edge = candidate_edges[best_doc_idx]
        best_score = best_result["hybrid_score"]

        best_id = best_node["id"]
        visited.add(best_id)

        path_entry = {
            "node_id": best_id,
            "node_type": best_node.get("type", ""),
            "text_preview": candidate_texts[best_doc_idx][:200],
            "similarity": best_score,
            "edge_rel": best_edge["rel"],
            "best_chunk": best_result.get("best_chunk", "")[:100],
        }
        path.append(path_entry)

        print(f"    步骤 {step + 1}: → {best_id} ({best_node.get('type', '?')}) "
              f"[{best_edge['rel']}] score={best_score:.4f}")

        # 如果到达 User 或 Data 节点，溯源完成
        if best_node.get("type") in ("User", "Data"):
            print(f"    ✅ 到达 {best_node.get('type')} 节点，溯源完成")
            break

        current_id = best_id

    # 反转路径：从源头到风险节点
    path.reverse()
    return path


def run_tracing(graph_path: str, detect_reports_path: str) -> dict:
    """加载检测报告中的告警节点，执行回溯。"""
    
    if not os.path.exists(detect_reports_path):
        print(f"❌ 找不到检测报告: {detect_reports_path}")
        print("请先执行 python -m core.detect 生成！")
        return {}
        
    with open(detect_reports_path, "r", encoding="utf-8") as f:
        detect_data = json.load(f)
        
    alerts = detect_data.get("alerts", [])
    if not alerts:
        print("✅ 检测报告中没有任何告警，无需回溯！")
        return {}
        
    print("=" * 70)
    print("🔙 AgentWeaver 攻击路径溯源")
    print(f"   检测报告: {detect_reports_path}")
    print(f"   图文件:   {graph_path}")
    print(f"   告警总数: {len(alerts)}")
    print("=" * 70)

    analyzer = GraphAnalyzer(graph_path)
    
    print("\n📦 加载 BGE-M3 模型与 BM25...")
    embedding_model = SentenceTransformer("BAAI/bge-m3")

    attack_paths = []
    traced_nodes = set()
    
    for alert in alerts:
        node_id = alert["node_id"]
        if node_id in traced_nodes:
            continue
        traced_nodes.add(node_id)

        print(f"\n📍 开始回溯风险节点: {node_id}")
        path = trace_attack_path(
            analyzer, node_id, embedding_model, alpha=0.5
        )
        attack_paths.append({
            "risk_node_id": node_id,
            "alert_rule": alert["rule"],
            "alert_message": alert["message"],
            "path": path,
        })
        
    report = {
        "timestamp": datetime.now().isoformat(),
        "graph_path": graph_path,
        "detect_reports_path": detect_reports_path,
        "traced_nodes_count": len(attack_paths),
        "attack_paths": attack_paths
    }
    
    return report
    
    
def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(script_dir)
    default_graph = os.path.join(project_root, "logs", "graph.json")
    default_detect_out = os.path.join(project_root, "logs", "detection_results.json")
    default_trace_out = os.path.join(project_root, "logs", "trace_results.json")

    parser = argparse.ArgumentParser(description="AgentWeaver 攻击路径溯源")
    parser.add_argument("--graph", default=default_graph,
                        help=f"图文件路径（默认: {default_graph}）")
    parser.add_argument("--detect-in", default=default_detect_out,
                        help=f"输入检测结果文件（默认: {default_detect_out}）")
    parser.add_argument("--out", default=default_trace_out,
                        help=f"溯源结果保存路径（默认: {default_trace_out}）")
    args = parser.parse_args()

    report = run_tracing(args.graph, args.detect_in)

    if report:
        if args.out:
            os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
            with open(args.out, "w", encoding="utf-8") as f:
                json.dump(report, f, ensure_ascii=False, indent=2)
            print(f"\n💾 溯源报告已保存到: {args.out}")
        else:
            print("\n📋 溯源报告 (JSON):")
            print(json.dumps(report, ensure_ascii=False, indent=2))

if __name__ == "__main__":
    main()
