#!/usr/bin/env python3
"""
Analisador de Logs de Acesso ao Servidor Web

Este script analisa os logs de acesso do servidor web para identificar padrões suspeitos
e possíveis técnicas de ataque.
"""

import re
from collections import defaultdict
from datetime import datetime

class LogAnalyzer:
    def __init__(self, log_file):
        self.log_file = log_file
        self.attacks_detected = 0
        self.suspicious_ips = defaultdict(int)
        self.common_patterns = {
            'sqli': r'(?i)(union\s+select|select\s+.*from|insert\s+into\s+\w+\s+values|delete\s+from|drop\s+table|xp_cmdshell)',
            'xss': r'(?i)(<script>|javascript:|<\/script>|alert\(|onerror=)',
            'lfi': r'(?i)(\.\./|\.\\|/etc/passwd|\\\\.\\.|\\\\.\\|\\x00)',
            'rce': r'(?i)(\$_(GET|POST|REQUEST)\[|system\(|exec\(|shell_exec\(|passthru\()',
            'path_traversal': r'(?i)(\.\./|\.\\)',
            'command_injection': r'(?i)(;\s*\b(rm|wget|curl|bash|sh|python|perl|ruby|nc|netcat|ncat|telnet)\b|\|\s*\b(rm|wget|curl|bash|sh|python|perl|ruby|nc|netcat|ncat|telnet)\b|`.*`|\$\s*\()',
            'webshell': r'(?i)(cmd\.exe|wget|curl|bash -i|/dev/tcp/|/bin/(ba)?sh|powershell\s+-nop\s+-c|IEX\s*\(|Invoke-WebRequest|Invoke-Shellcode|Invoke-Mimikatz|Invoke-PowerShellTcp)'
        }
        self.log_entries = []

    def parse_log_line(self, line):
        """Parse a single log line into its components."""
        # Common Log Format: IP - - [timestamp] "method path protocol" status size
        pattern = r'(\S+) - - \[(.*?)\] "(\S+) (\S+) (\S+)" (\d+) (\d+)'
        match = re.match(pattern, line)
        
        if not match:
            return None
            
        ip, timestamp, method, path, protocol, status, size = match.groups()
        
        # Convert timestamp to datetime object
        try:
            timestamp = datetime.strptime(timestamp, '%d/%b/%Y:%H:%M:%S %z')
        except ValueError:
            timestamp = datetime.strptime(timestamp, '%d/%b/%Y:%H:%M:%S')
            
        return {
            'ip': ip,
            'timestamp': timestamp,
            'method': method,
            'path': path,
            'protocol': protocol,
            'status': int(status),
            'size': int(size) if size.isdigit() else 0,
            'raw': line.strip()
        }

    def analyze_line(self, entry):
        """Analyze a single log entry for suspicious patterns."""
        if not entry:
            return
            
        suspicious = False
        details = []
        
        # Check for suspicious patterns in the request path
        for pattern_name, pattern in self.common_patterns.items():
            if re.search(pattern, entry['path'] + ' ' + entry.get('user_agent', '')):
                suspicious = True
                details.append(f"Detected {pattern_name.upper()} pattern")
                self.attacks_detected += 1
                self.suspicious_ips[entry['ip']] += 1
        
        # Check for suspicious status codes
        if entry['status'] in [401, 403, 404, 500, 502, 503]:
            details.append(f"Suspicious status code: {entry['status']}")
        
        # Check for suspicious HTTP methods
        if entry['method'] not in ['GET', 'POST', 'HEAD', 'OPTIONS']:
            details.append(f"Unusual HTTP method: {entry['method']}")
        
        # Check for excessive requests from a single IP
        if self.suspicious_ips[entry['ip']] > 10:  # Threshold of 10 requests
            details.append(f"Excessive requests from IP: {entry['ip']}")
        
        if suspicious or details:
            print(f"\n[!] Suspicious activity detected:")
            print(f"    IP: {entry['ip']}")
            print(f"    Time: {entry['timestamp']}")
            print(f"    Request: {entry['method']} {entry['path']}")
            print(f"    Status: {entry['status']}")
            for detail in details:
                print(f"    - {detail}")
    
    def analyze_logs(self):
        """Analyze all log entries in the log file."""
        print(f"[+] Analyzing log file: {self.log_file}")
        
        try:
            with open(self.log_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    entry = self.parse_log_line(line)
                    if entry:
                        self.log_entries.append(entry)
                        self.analyze_line(entry)
        except FileNotFoundError:
            print(f"[!] Error: File not found: {self.log_file}")
            return
        
        print("\n[+] Analysis complete!")
        print(f"    Total log entries: {len(self.log_entries)}")
        print(f"    Potential attacks detected: {self.attacks_detected}")
        
        if self.suspicious_ips:
            print("\n[+] Suspicious IPs:")
            for ip, count in sorted(self.suspicious_ips.items(), key=lambda x: x[1], reverse=True):
                print(f"    {ip}: {count} suspicious activities")

    def generate_report(self, output_file):
        """Generate a detailed report of the analysis."""
        with open(output_file, 'w') as f:
            f.write("# Análise de Logs de Acesso ao Servidor Web\n\n")
            f.write(f"## Resumo da Análise\n")
            f.write(f"- Arquivo analisado: {self.log_file}\n")
            f.write(f"- Total de entradas de log: {len(self.log_entries)}\n")
            f.write(f"- Ataques potenciais detectados: {self.attacks_detected}\n")
            f.write(f"- IPs suspeitos identificados: {len(self.suspicious_ips)}\n\n")
            
            if self.suspicious_ips:
                f.write("## IPs Suspeitos\n")
                f.write("| IP | Atividades Suspeitas |\n")
                f.write("|----|----------------------|\n")
                for ip, count in sorted(self.suspicious_ips.items(), key=lambda x: x[1], reverse=True):
                    f.write(f"| {ip} | {count} |\n")
                f.write("\n")
            
            f.write("## Padrões de Ameaças Detectados\n")
            for entry in self.log_entries:
                for pattern_name, pattern in self.common_patterns.items():
                    if re.search(pattern, entry['path'] + ' ' + entry.get('user_agent', '')):
                        f.write(f"### Padrão: {pattern_name.upper()}\n")
                        f.write(f"- **IP**: {entry['ip']}\n")
                        f.write(f"- **Data/Hora**: {entry['timestamp']}\n")
                        f.write(f"- **Requisição**: {entry['method']} {entry['path']}\n")
                        f.write(f"- **Status**: {entry['status']}\n")
                        f.write(f"- **Linha do Log**: `{entry['raw']}`\n\n")
            
            f.write("## Recomendações de Segurança\n")
            f.write("1. **Atualizações de Segurança**\n")
            f.write("   - Aplique imediatamente todas as atualizações de segurança disponíveis para o servidor web e aplicações.\n\n")
            f.write("2. **Regras de Firewall**\n")
            f.write("   - Bloqueie os endereços IPs maliciosos identificados.\n")
            f.write("   - Implemente regras para limitar as taxas de requisição.\n\n")
            f.write("3. **Hardening do Servidor**\n")
            f.write("   - Desative métodos HTTP desnecessários (como TRACE, DELETE, PUT).\n")
            f.write("   - Implemente o cabeçalho de segurança HTTP Strict Transport Security (HSTS).\n\n")
            f.write("4. **Monitoramento Contínuo**\n")
            f.write("   - Configure alertas para padrões de ataque conhecidos.\n")
            f.write("   - Implemente uma solução de SIEM para análise avançada de logs.\n")
            
            f.write("\n---\n")
            f.write(f"Relatório gerado em: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <log_file> [output_report]")
        sys.exit(1)
    
    log_file = sys.argv[1]
    output_report = sys.argv[2] if len(sys.argv) > 2 else "relatorio_analise_logs.md"
    
    analyzer = LogAnalyzer(log_file)
    analyzer.analyze_logs()
    analyzer.generate_report(output_report)
    print(f"\n[+] Relatório gerado: {output_report}")
