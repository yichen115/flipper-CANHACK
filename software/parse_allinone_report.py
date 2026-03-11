#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CANHACK UDS ALLINONE Report Parser
解析UDS测试报告并生成美观的网页报告
"""

import re
import sys
import json
from datetime import datetime
from pathlib import Path


# 测试项目说明
TEST_DESCRIPTIONS = {
    'ECU Discovery': {
        'title': 'ECU发现',
        'icon': 'fa-search',
        'color': '#3B82F6',
        'description': '通过发送诊断会话控制请求(0x10 0x01)扫描指定CAN ID范围内的ECU设备。发现响应正响应(0x50)或负响应(0x7F)的节点。',
        'details': [
            '发送请求: 02 10 01 (请求默认会话)',
            '期望响应: 50 01 xx xx (正响应)',
            '扫描范围可配置起始和结束CAN ID'
        ]
    },
    'Session': {
        'title': '诊断会话',
        'icon': 'fa-exchange-alt',
        'color': '#10B981',
        'description': '测试不同的诊断会话类型，包括默认会话、编程会话、扩展会话和安全系统会话。每个会话可能有不同的访问权限。',
        'details': [
            'Default (0x01): 默认会话，基础诊断功能',
            'Programming (0x02): 编程会话，用于固件更新',
            'Extended (0x03): 扩展会话，高级诊断功能',
            'Safety (0x04): 安全系统会话，访问受限功能'
        ]
    },
    'DID Scan': {
        'title': 'DID扫描',
        'icon': 'fa-database',
        'color': '#8B5CF6',
        'description': '读取数据标识符(Data Identifier)来发现ECU中存储的数据。DID用于存储车辆信息、配置参数、传感器数据等。',
        'details': [
            '服务: 0x22 (ReadDataByIdentifier)',
            '扫描范围: 0xF190-0xF1A0, 0xF1B0-0xF1C0等',
            '常见DID: F190(VIN), F193(供应商硬件版本), F195(软件版本)',
            '响应0x62表示DID存在并可读取'
        ]
    },
    'Security Access': {
        'title': '安全访问',
        'icon': 'fa-shield-alt',
        'color': '#F59E0B',
        'description': '测试安全访问级别，通过请求种子(Seed)并计算密钥(Key)来解锁受保护的功能。这是UDS安全机制的核心。',
        'details': [
            '请求种子: 27 0x (奇数级别)',
            '发送密钥: 27 0x+1 (偶数级别)',
            '尝试算法: NOT, XOR 0x00-0xFF, Level3 Complex',
            '成功解锁后可访问受保护的数据和功能'
        ]
    }
}


def parse_report(file_path):
    """解析ALLINONE报告文件"""
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    report = {
        'date': '',
        'scan_range': '',
        'ecus': []
    }
    
    # 解析头部信息
    date_match = re.search(r'Date: (.+)', content)
    if date_match:
        report['date'] = date_match.group(1)
    
    range_match = re.search(r'Scan Range: (.+)', content)
    if range_match:
        report['scan_range'] = range_match.group(1)
    
    # 解析每个ECU
    ecu_sections = re.split(r'=== ECU \d+ ===', content)[1:]
    
    for ecu_section in ecu_sections:
        ecu = {
            'tx_id': '',
            'rx_id': '',
            'sessions': []
        }
        
        # 解析ECU ID
        tx_match = re.search(r'TX ID: (.+)', ecu_section)
        rx_match = re.search(r'RX ID: (.+)', ecu_section)
        if tx_match:
            ecu['tx_id'] = tx_match.group(1).strip()
        if rx_match:
            ecu['rx_id'] = rx_match.group(1).strip()
        
        # 解析会话
        session_sections = re.split(r'--- (.+?) Session', ecu_section)[1:]
        
        for i in range(0, len(session_sections), 2):
            if i + 1 >= len(session_sections):
                break
            
            session_name = session_sections[i].strip()
            session_content = session_sections[i + 1]
            
            session = {
                'name': session_name,
                'dids': [],
                'security_levels': []
            }
            
            # 解析DID
            did_section = re.search(r'\[DID Scan\](.+?)(?=\[Security Access\]|---|$)', 
                                   session_content, re.DOTALL)
            if did_section:
                did_matches = re.findall(r'0x([0-9A-F]{4})', did_section.group(1))
                session['dids'] = ['0x' + did for did in did_matches]
            
            # 解析安全访问 - 更新以支持ALGO字段
            security_section = re.search(r'\[Security Access\](.+?)(?=---|$)', 
                                        session_content, re.DOTALL)
            if security_section:
                lines = security_section.group(1).strip().split('\n')
                for line in lines:
                    line = line.strip()
                    if not line or line.startswith('['):
                        continue
                    
                    # 格式1: Level XX: NOT_SUPPORTED (NRC 0xXX)
                    not_supported = re.match(r'Level\s+(\w+):\s+NOT_SUPPORTED\s+\(NRC\s+0x(\w+)\)', line)
                    if not_supported:
                        session['security_levels'].append({
                            'level': not_supported.group(1),
                            'status': 'NOT_SUPPORTED',
                            'nrc': '0x' + not_supported.group(2)
                        })
                        continue
                    
                    # 格式2: Level XX: SEED=0xXXXX, KEY=0xXXXX, ALGO=XXX
                    with_algo = re.match(r'Level\s+(\w+):\s+SEED=(0x\w+),\s+KEY=(\w+),\s+ALGO=(.+)', line)
                    if with_algo:
                        session['security_levels'].append({
                            'level': with_algo.group(1),
                            'status': 'TESTED',
                            'seed': with_algo.group(2),
                            'key': with_algo.group(3),
                            'algo': with_algo.group(4).strip()
                        })
                        continue
                    
                    # 格式3: Level XX: SEED=0xXXXX, KEY=NOT_FOUND (tried X algorithms)
                    not_found = re.match(r'Level\s+(\w+):\s+SEED=(0x\w+),\s+KEY=NOT_FOUND\s*\(tried\s+(\d+)\s+algorithms\)', line)
                    if not_found:
                        session['security_levels'].append({
                            'level': not_found.group(1),
                            'status': 'NOT_FOUND',
                            'seed': not_found.group(2),
                            'attempts': int(not_found.group(3))
                        })
                        continue
                    
                    # 格式4: Level XX: LOCKED (NRC 0xXX)
                    locked = re.match(r'Level\s+(\w+):\s+LOCKED\s+\(NRC\s+0x(\w+)\)', line)
                    if locked:
                        session['security_levels'].append({
                            'level': locked.group(1),
                            'status': 'LOCKED',
                            'nrc': '0x' + locked.group(2)
                        })
            
            ecu['sessions'].append(session)
        
        report['ecus'].append(ecu)
    
    return report


def generate_stats(report):
    """生成统计数据"""
    stats = {
        'total_ecus': len(report['ecus']),
        'total_sessions': 0,
        'total_dids': 0,
        'total_security_levels': 0,
        'supported_security_levels': 0,
        'locked_levels': 0,
        'successful_bruteforce': 0,
        'failed_bruteforce': 0,
        'session_breakdown': {}
    }
    
    for ecu in report['ecus']:
        for session in ecu['sessions']:
            stats['total_sessions'] += 1
            stats['total_dids'] += len(session['dids'])
            stats['total_security_levels'] += len(session['security_levels'])
            
            session_type = session['name'].split('(')[0].strip()
            if session_type not in stats['session_breakdown']:
                stats['session_breakdown'][session_type] = {
                    'count': 0,
                    'dids': 0,
                    'security_levels': 0
                }
            stats['session_breakdown'][session_type]['count'] += 1
            stats['session_breakdown'][session_type]['dids'] += len(session['dids'])
            stats['session_breakdown'][session_type]['security_levels'] += len(session['security_levels'])
            
            for level in session['security_levels']:
                if level['status'] == 'TESTED':
                    stats['supported_security_levels'] += 1
                    stats['successful_bruteforce'] += 1
                elif level['status'] == 'NOT_FOUND':
                    stats['supported_security_levels'] += 1
                    stats['failed_bruteforce'] += 1
                elif level['status'] == 'LOCKED':
                    stats['locked_levels'] += 1
    
    return stats


def generate_html(report, stats, output_path):
    """生成美观的HTML报告"""
    
    html_template = '''<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CANHACK UDS ALLINONE 测试报告</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        body {{ font-family: 'Inter', sans-serif; background: #f8fafc; }}
        .card {{ background: white; border-radius: 12px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); transition: all 0.2s; }}
        .card:hover {{ box-shadow: 0 4px 12px rgba(0,0,0,0.15); }}
        .badge {{ display: inline-flex; align-items: center; gap: 4px; padding: 4px 10px; border-radius: 20px; font-size: 12px; font-weight: 500; }}
        .copy-btn {{ cursor: pointer; transition: all 0.2s; }}
        .copy-btn:hover {{ transform: scale(1.1); }}
        .section-title {{ font-size: 14px; font-weight: 600; color: #64748b; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 12px; }}
        .info-box {{ background: #f1f5f9; border-left: 3px solid #3b82f6; padding: 12px 16px; border-radius: 0 8px 8px 0; margin: 8px 0; }}
        .info-box-title {{ font-weight: 600; color: #1e293b; margin-bottom: 4px; font-size: 13px; }}
        .info-box-desc {{ color: #64748b; font-size: 12px; line-height: 1.5; }}
        .info-box-details {{ margin-top: 8px; padding-top: 8px; border-top: 1px dashed #cbd5e1; }}
        .info-box-details li {{ color: #475569; font-size: 11px; margin: 4px 0; }}
        .chart-container {{ position: relative; height: 180px; }}
        .did-tag {{ display: inline-block; padding: 2px 8px; background: #e0e7ff; color: #4338ca; border-radius: 4px; font-size: 11px; margin: 2px; }}
        .status-success {{ background: #dcfce7; color: #166534; }}
        .status-failed {{ background: #fee2e2; color: #991b1b; }}
        .status-locked {{ background: #fef3c7; color: #92400e; }}
        .status-unsupported {{ background: #f3f4f6; color: #6b7280; }}
        .fade-in {{ animation: fadeIn 0.4s ease-out; }}
        @keyframes fadeIn {{ from {{ opacity: 0; transform: translateY(10px); }} to {{ opacity: 1; transform: translateY(0); }} }}
        .grid-4 {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; }}
        @media (max-width: 1024px) {{ .grid-4 {{ grid-template-columns: repeat(2, 1fr); }} }}
        @media (max-width: 640px) {{ .grid-4 {{ grid-template-columns: 1fr; }} }}
    </style>
</head>
<body class="min-h-screen">
    <!-- Header -->
    <header style="background: linear-gradient(135deg, #1e3a8a 0%, #3b82f6 100%);" class="text-white py-6">
        <div class="max-w-7xl mx-auto px-6">
            <div class="flex items-center justify-between">
                <div>
                    <div class="flex items-center gap-3 mb-1">
                        <i class="fas fa-car-side text-2xl"></i>
                        <h1 class="text-2xl font-bold">CANHACK UDS ALLINONE</h1>
                    </div>
                    <p class="text-blue-100 text-sm">车辆诊断安全测试报告</p>
                </div>
                <div class="text-right text-sm">
                    <div class="text-blue-100">{date}</div>
                    <div class="mt-1">{scan_range}</div>
                </div>
            </div>
        </div>
    </header>

    <main class="max-w-7xl mx-auto px-6 py-6">
        <!-- 测试说明 -->
        <section class="mb-8 fade-in">
            <div class="section-title"><i class="fas fa-info-circle mr-2"></i>测试项目说明</div>
            <div class="grid-4">
                {test_descriptions}
            </div>
        </section>

        <!-- 统计概览 -->
        <section class="mb-8 fade-in">
            <div class="section-title"><i class="fas fa-chart-pie mr-2"></i>统计概览</div>
            <div class="grid-4">
                <div class="card p-4">
                    <div class="flex items-center gap-3">
                        <div class="w-10 h-10 rounded-lg bg-blue-100 flex items-center justify-center">
                            <i class="fas fa-microchip text-blue-600"></i>
                        </div>
                        <div>
                            <div class="text-2xl font-bold text-gray-800">{total_ecus}</div>
                            <div class="text-xs text-gray-500">发现ECU</div>
                        </div>
                    </div>
                </div>
                <div class="card p-4">
                    <div class="flex items-center gap-3">
                        <div class="w-10 h-10 rounded-lg bg-green-100 flex items-center justify-center">
                            <i class="fas fa-exchange-alt text-green-600"></i>
                        </div>
                        <div>
                            <div class="text-2xl font-bold text-gray-800">{total_sessions}</div>
                            <div class="text-xs text-gray-500">测试会话</div>
                        </div>
                    </div>
                </div>
                <div class="card p-4">
                    <div class="flex items-center gap-3">
                        <div class="w-10 h-10 rounded-lg bg-purple-100 flex items-center justify-center">
                            <i class="fas fa-database text-purple-600"></i>
                        </div>
                        <div>
                            <div class="text-2xl font-bold text-gray-800">{total_dids}</div>
                            <div class="text-xs text-gray-500">发现DID</div>
                        </div>
                    </div>
                </div>
                <div class="card p-4">
                    <div class="flex items-center gap-3">
                        <div class="w-10 h-10 rounded-lg bg-orange-100 flex items-center justify-center">
                            <i class="fas fa-shield-alt text-orange-600"></i>
                        </div>
                        <div>
                            <div class="text-2xl font-bold text-gray-800">{supported_security_levels}</div>
                            <div class="text-xs text-gray-500">安全级别</div>
                        </div>
                    </div>
                </div>
            </div>
        </section>

        <!-- 图表 - 更小的尺寸 -->
        <section class="mb-8 fade-in">
            <div class="section-title"><i class="fas fa-chart-bar mr-2"></i>数据分析</div>
            <div class="grid grid-cols-1 lg:grid-cols-3 gap-4">
                <div class="card p-4">
                    <div class="text-sm font-medium text-gray-600 mb-3">会话分布</div>
                    <div class="chart-container">
                        <canvas id="sessionChart"></canvas>
                    </div>
                </div>
                <div class="card p-4">
                    <div class="text-sm font-medium text-gray-600 mb-3">安全访问状态</div>
                    <div class="chart-container">
                        <canvas id="securityChart"></canvas>
                    </div>
                </div>
                <div class="card p-4">
                    <div class="text-sm font-medium text-gray-600 mb-3">密钥爆破结果</div>
                    <div class="chart-container">
                        <canvas id="bruteforceChart"></canvas>
                    </div>
                </div>
            </div>
        </section>

        <!-- ECU详情 -->
        <section class="fade-in">
            <div class="section-title"><i class="fas fa-microchip mr-2"></i>ECU 详细信息</div>
            {ecu_details}
        </section>
    </main>

    <!-- Footer -->
    <footer class="bg-white border-t mt-12 py-4">
        <div class="max-w-7xl mx-auto px-6 text-center text-xs text-gray-400">
            CANHACK UDS ALLINONE Report Parser &bull; {timestamp}
        </div>
    </footer>

    <script>
        // Session Chart
        new Chart(document.getElementById('sessionChart'), {{
            type: 'doughnut',
            data: {{
                labels: {session_labels},
                datasets: [{{
                    data: {session_data},
                    backgroundColor: ['#3b82f6', '#10b981', '#8b5cf6', '#f59e0b'],
                    borderWidth: 0
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                plugins: {{ legend: {{ position: 'bottom', labels: {{ boxWidth: 12, font: {{ size: 10 }} }} }} }}
            }}
        }});

        // Security Chart
        new Chart(document.getElementById('securityChart'), {{
            type: 'bar',
            data: {{
                labels: ['支持', '不支持', '锁定'],
                datasets: [{{
                    data: {security_data},
                    backgroundColor: ['#10b981', '#ef4444', '#f59e0b'],
                    borderRadius: 4
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                plugins: {{ legend: {{ display: false }} }},
                scales: {{ y: {{ beginAtZero: true, ticks: {{ font: {{ size: 10 }} }} }}, x: {{ ticks: {{ font: {{ size: 10 }} }} }} }}
            }}
        }});

        // Bruteforce Chart
        new Chart(document.getElementById('bruteforceChart'), {{
            type: 'pie',
            data: {{
                labels: ['成功', '失败'],
                datasets: [{{
                    data: {bruteforce_data},
                    backgroundColor: ['#3b82f6', '#9ca3af'],
                    borderWidth: 0
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                plugins: {{ legend: {{ position: 'bottom', labels: {{ boxWidth: 12, font: {{ size: 10 }} }} }} }}
            }}
        }});

        // Copy function
        function copy(text) {{
            navigator.clipboard.writeText(text).then(() => {{
                const toast = document.createElement('div');
                toast.className = 'fixed bottom-4 right-4 bg-green-500 text-white px-4 py-2 rounded-lg shadow-lg text-sm z-50';
                toast.innerHTML = '<i class="fas fa-check mr-2"></i>已复制';
                document.body.appendChild(toast);
                setTimeout(() => toast.remove(), 1500);
            }});
        }}
    </script>
</body>
</html>'''

    # 生成测试说明HTML
    test_desc_html = ''
    for key, desc in TEST_DESCRIPTIONS.items():
        details_html = ''.join([f'<li><i class="fas fa-angle-right mr-1 text-gray-400"></i>{d}</li>' for d in desc['details']])
        test_desc_html += f'''
        <div class="card p-4">
            <div class="flex items-center gap-2 mb-2">
                <i class="fas {desc['icon']}" style="color: {desc['color']}"></i>
                <span class="font-semibold text-sm">{desc['title']}</span>
            </div>
            <div class="info-box" style="border-left-color: {desc['color']}">
                <div class="info-box-desc">{desc['description']}</div>
                <div class="info-box-details">
                    <ul class="list-none">{details_html}</ul>
                </div>
            </div>
        </div>'''

    # 生成ECU详细信息HTML
    ecu_details_html = ''
    for idx, ecu in enumerate(report['ecus'], 1):
        sessions_html = ''
        for session in ecu['sessions']:
            # DID列表
            dids_html = ''
            if session['dids']:
                dids_tags = ''.join([f'<span class="did-tag">{did}</span>' for did in session['dids']])
                dids_html = f'''
                <div class="mt-3">
                    <div class="flex items-center justify-between mb-2">
                        <span class="text-xs font-medium text-gray-500">发现 {len(session['dids'])} 个DID</span>
                        <button onclick="copy('{', '.join(session['dids'])}')" class="copy-btn text-blue-500 text-xs">
                            <i class="fas fa-copy"></i> 复制
                        </button>
                    </div>
                    <div class="flex flex-wrap">{dids_tags}</div>
                </div>'''
            
            # 安全级别列表
            security_html = ''
            if session['security_levels']:
                security_rows = ''
                for level in session['security_levels']:
                    if level['status'] == 'TESTED':
                        status_class = 'status-success'
                        status_text = '成功'
                        details = f"Key: {level['key']}, {level.get('algo', 'N/A')}"
                    elif level['status'] == 'NOT_FOUND':
                        status_class = 'status-failed'
                        status_text = '失败'
                        details = f"尝试258种算法未找到"
                    elif level['status'] == 'LOCKED':
                        status_class = 'status-locked'
                        status_text = '锁定'
                        details = f"NRC: {level['nrc']}"
                    else:  # NOT_SUPPORTED
                        status_class = 'status-unsupported'
                        status_text = '不支持'
                        details = f"NRC: {level['nrc']}"
                    
                    security_rows += f'''
                    <tr class="border-b border-gray-100 text-sm">
                        <td class="py-2 px-3 font-medium">L{level['level']}</td>
                        <td class="py-2 px-3"><span class="badge {status_class}">{status_text}</span></td>
                        <td class="py-2 px-3 text-gray-600 text-xs">{details}</td>
                        <td class="py-2 px-3">
                            <button onclick="copy('Level {level['level']}: Seed {level.get('seed', 'N/A')}')" class="copy-btn text-gray-400 hover:text-blue-500">
                                <i class="fas fa-copy"></i>
                            </button>
                        </td>
                    </tr>'''
                
                security_html = f'''
                <div class="mt-4">
                    <div class="text-xs font-medium text-gray-500 mb-2">安全访问测试</div>
                    <table class="w-full">
                        <thead>
                            <tr class="text-xs text-gray-500 border-b">
                                <th class="py-1 px-3 text-left">级别</th>
                                <th class="py-1 px-3 text-left">状态</th>
                                <th class="py-1 px-3 text-left">详情</th>
                                <th class="py-1 px-3 text-left"></th>
                            </tr>
                        </thead>
                        <tbody>{security_rows}</tbody>
                    </table>
                </div>'''
            
            sessions_html += f'''
            <div class="border-t pt-3 mt-3">
                <div class="flex items-center justify-between">
                    <span class="font-medium text-sm text-gray-700">{session['name']}</span>
                    <div class="flex gap-2">
                        <span class="badge bg-purple-100 text-purple-700">{len(session['dids'])} DIDs</span>
                        <span class="badge bg-orange-100 text-orange-700">{len(session['security_levels'])} 安全</span>
                    </div>
                </div>
                {dids_html}
                {security_html}
            </div>'''
        
        ecu_details_html += f'''
        <div class="card mb-4 overflow-hidden">
            <div class="bg-gradient-to-r from-slate-700 to-slate-600 text-white px-4 py-3">
                <div class="flex items-center justify-between">
                    <div class="flex items-center gap-2">
                        <i class="fas fa-microchip"></i>
                        <span class="font-semibold">ECU {idx}</span>
                    </div>
                    <button onclick="copy('TX: {ecu['tx_id']}, RX: {ecu['rx_id']}')" class="copy-btn text-white/70 hover:text-white text-xs">
                        <i class="fas fa-copy"></i> 复制ID
                    </button>
                </div>
                <div class="mt-1 text-xs text-white/70 flex gap-4">
                    <span><i class="fas fa-arrow-up mr-1"></i>{ecu['tx_id']}</span>
                    <span><i class="fas fa-arrow-down mr-1"></i>{ecu['rx_id']}</span>
                </div>
            </div>
            <div class="p-4">
                {sessions_html}
            </div>
        </div>'''

    # 准备图表数据
    session_labels = list(stats['session_breakdown'].keys())
    session_data = [stats['session_breakdown'][s]['count'] for s in session_labels]
    
    not_supported = stats['total_security_levels'] - stats['supported_security_levels'] - stats['locked_levels']
    security_data = [
        stats['supported_security_levels'],
        max(0, not_supported),
        stats['locked_levels']
    ]
    
    bruteforce_data = [
        stats['successful_bruteforce'],
        stats['failed_bruteforce']
    ]

    # 填充模板
    html = html_template.format(
        date=report['date'],
        scan_range=report['scan_range'],
        total_ecus=stats['total_ecus'],
        total_sessions=stats['total_sessions'],
        total_dids=stats['total_dids'],
        supported_security_levels=stats['supported_security_levels'],
        timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        test_descriptions=test_desc_html,
        session_labels=json.dumps(session_labels),
        session_data=json.dumps(session_data),
        security_data=json.dumps(security_data),
        bruteforce_data=json.dumps(bruteforce_data),
        ecu_details=ecu_details_html
    )

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html)


def main():
    if len(sys.argv) < 2:
        input_file = r'ALLINONE_20260310_233249.txt'
    else:
        input_file = sys.argv[1]
    
    input_path = Path(input_file)
    if not input_path.exists():
        print(f"错误: 文件不存在: {input_file}")
        sys.exit(1)
    
    output_file = input_path.stem + '.html'
    output_path = input_path.parent / output_file
    
    print(f"正在解析报告: {input_file}")
    report = parse_report(input_file)
    
    print("正在生成统计数据...")
    stats = generate_stats(report)
    
    print(f"正在生成HTML报告: {output_path}")
    generate_html(report, stats, output_path)
    
    print(f"\n完成! 报告已保存到: {output_path}")
    print(f"\n统计摘要:")
    print(f"  - 发现ECU: {stats['total_ecus']} 个")
    print(f"  - 测试会话: {stats['total_sessions']} 个")
    print(f"  - 发现DID: {stats['total_dids']} 个")
    print(f"  - 支持的安全级别: {stats['supported_security_levels']} 个")
    print(f"  - 爆破成功: {stats['successful_bruteforce']} 个")
    print(f"  - 爆破失败: {stats['failed_bruteforce']} 个")


if __name__ == '__main__':
    main()
