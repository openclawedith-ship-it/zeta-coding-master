#!/usr/bin/env python3
"""
⚡ ZETA Runner — Batch code generation for R&D
Runs the coding master multiple times, generates code in all languages
"""

import sys
import json
import random
import argparse
from datetime import datetime
from pathlib import Path

# Import the main system
sys.path.insert(0, str(Path(__file__).parent))
from zeta_ultimate import ZetaCodingMaster, ULTIMATE_LANGUAGE_REGISTRY

# Problems to solve (rotates through these)
PROBLEMS = [
    "binary search algorithm",
    "quicksort implementation",
    "linked list with insert/delete",
    "hashmap with collision handling",
    "binary tree traversal (BFS/DFS)",
    "dijkstra shortest path",
    "dynamic programming fibonacci",
    "LRU cache implementation",
    "merge sort algorithm",
    "stack with min() in O(1)",
    "queue using two stacks",
    "graph adjacency list",
    "trie data structure",
    "heap sort algorithm",
    "two sum problem",
    "longest common subsequence",
    "edit distance algorithm",
    "knapsack problem",
    "coin change problem",
    "matrix chain multiplication",
    "topological sort",
    "bellman-ford algorithm",
    "kruskal minimum spanning tree",
    "A* pathfinding algorithm",
    "producer-consumer pattern",
    "rate limiter implementation",
    "URL shortener backend",
    "chat server (websocket)",
    "file encryption tool",
    "DNS resolver",
    "HTTP server from scratch",
    "TCP port scanner",
    "JSON parser",
    "markdown to HTML converter",
    "regex engine basics",
    "base64 encoder/decoder",
    "gzip compression",
    "RSA key generation",
    "SHA-256 implementation",
    "UUID generator",
    "CRUD REST API",
    "JWT authentication",
    "WebSocket chat",
    "Redis clone",
    "Task scheduler",
    "Log analyzer",
    "CSV parser",
    "Template engine",
    "CLI argument parser",
    "Config file reader",
    "Code formatter",
    "Syntax highlighter",
    "Diff algorithm",
    "Cron expression parser",
    "QR code generator",
    "Image resizer",
    "PDF generator",
    "Email validator",
    "Password strength checker",
    "2FA TOTP generator",
]

# Languages to generate (the ones we have engines for)
LANGUAGES = ["python", "javascript", "rust", "go", "c", "x86_assembly"]

def run_batch(batch_size=4, output_dir="generated"):
    """Run a batch of code generation"""
    output = Path(output_dir)
    output.mkdir(exist_ok=True)
    
    master = ZetaCodingMaster()
    
    log = {
        "timestamp": datetime.now().isoformat(),
        "batch_size": batch_size,
        "runs": []
    }
    
    for i in range(batch_size):
        problem = random.choice(PROBLEMS)
        language = random.choice(LANGUAGES)
        
        run_id = f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{i:03d}"
        
        print(f"\n{'='*60}")
        print(f"⚡ Run {i+1}/{batch_size}: {language} → {problem}")
        print(f"{'='*60}")
        
        try:
            # Generate code
            code = master.generate_code(language, problem)
            
            if isinstance(code, dict):
                code_str = code.get("code", str(code))
            else:
                code_str = str(code)
            
            # Save generated code
            ext = ULTIMATE_LANGUAGE_REGISTRY.get(language, {}).get("ext", "txt")
            filename = f"{run_id}_{language}_{problem[:30].replace(' ','_').replace('/','_').replace('(','').replace(')','')}.{ext}"
            filepath = output / filename
            filepath.write_text(code_str)
            
            # Get complexity
            complexity = master.analyze_complexity(problem.split()[0])
            
            run_log = {
                "id": run_id,
                "language": language,
                "problem": problem,
                "code_length": len(code_str),
                "file": str(filename),
                "complexity": complexity,
                "status": "success"
            }
            
            print(f"✅ Generated {len(code_str)} chars → {filename}")
            
        except Exception as e:
            run_log = {
                "id": run_id,
                "language": language,
                "problem": problem,
                "error": str(e),
                "status": "failed"
            }
            print(f"❌ Error: {e}")
        
        log["runs"].append(run_log)
    
    # Save log
    log_file = output.parent / "logs" / f"batch_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    log_file.parent.mkdir(exist_ok=True)
    log_file.write_text(json.dumps(log, indent=2))
    
    # Summary
    success = sum(1 for r in log["runs"] if r["status"] == "success")
    failed = sum(1 for r in log["runs"] if r["status"] == "failed")
    total_chars = sum(r.get("code_length", 0) for r in log["runs"])
    
    print(f"\n{'='*60}")
    print(f"📊 BATCH COMPLETE")
    print(f"   ✅ Success: {success}/{batch_size}")
    print(f"   ❌ Failed: {failed}/{batch_size}")
    print(f"   📝 Total code: {total_chars:,} chars")
    print(f"   📁 Output: {output}")
    print(f"{'='*60}")
    
    return log

def run_continuous(total_runs=100, batch_size=4):
    """Run multiple batches to reach total_runs"""
    batches = (total_runs + batch_size - 1) // batch_size
    
    print(f"""
╔══════════════════════════════════════════════════════════════╗
║  ⚡ ZETA CODING MASTER — CONTINUOUS R&D MODE                 ║
║                                                              ║
║  Total runs: {total_runs}                                       ║
║  Batch size: {batch_size}                                        ║
║  Batches: {batches}                                            ║
║  Languages: {', '.join(LANGUAGES)}                            ║
║  Problems: {len(PROBLEMS)} available                          ║
╚══════════════════════════════════════════════════════════════╝
""")
    
    all_logs = []
    for batch_num in range(batches):
        remaining = total_runs - (batch_num * batch_size)
        current_batch = min(batch_size, remaining)
        
        print(f"\n🚀 BATCH {batch_num + 1}/{batches}")
        log = run_batch(current_batch)
        all_logs.append(log)
    
    # Final summary
    total_success = sum(sum(1 for r in l["runs"] if r["status"] == "success") for l in all_logs)
    total_code = sum(sum(r.get("code_length", 0) for r in l["runs"]) for l in all_logs)
    
    print(f"\n{'='*60}")
    print(f"🎯 FINAL RESULTS")
    print(f"   Total runs: {total_runs}")
    print(f"   Success: {total_success}/{total_runs}")
    print(f"   Total code generated: {total_code:,} chars")
    print(f"   Files: {len(list(Path('generated').glob('*')))} files")
    print(f"{'='*60}")
    
    # Save summary
    summary = {
        "timestamp": datetime.now().isoformat(),
        "total_runs": total_runs,
        "success": total_success,
        "total_code_chars": total_code,
        "languages_used": LANGUAGES,
        "problems_solved": len(PROBLEMS),
    }
    Path("logs/summary.json").write_text(json.dumps(summary, indent=2))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ZETA Coding Master Runner")
    parser.add_argument("--batch", type=int, default=4, help="Batch size")
    parser.add_argument("--total", type=int, default=100, help="Total runs")
    parser.add_argument("--output", type=str, default="generated", help="Output directory")
    parser.add_argument("--continuous", action="store_true", help="Run continuously")
    
    args = parser.parse_args()
    
    if args.continuous:
        run_continuous(args.total, args.batch)
    else:
        run_batch(args.batch, args.output)
