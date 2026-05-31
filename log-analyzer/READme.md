# Log Analyzer — Web Server Attack Detection

A Python tool that parses Apache/Nginx access logs, detects attack patterns,
enriches suspicious IPs with AbuseIPDB reputation data, and delivers alerts
via Telegram with a PDF report.

Built as part of a cybersecurity portfolio for academic evaluation.

## Features

- Parses Apache/Nginx Combined Log Format
- Detects common attack patterns:
  - Brute force (repeated 401/403)
  - SQL Injection attempts
  - Path traversal
  - Vulnerability scanning (sequential 404s)
- IP reputation check via AbuseIPDB API (https://www.abuseipdb.com -> Login and API key)
- Real-time Telegram alerts for critical events
- PDF report generation with attack summary

## requirements.txt
requests — para chamar a AbuseIPDB API e o Telegram
fpdf2 — para gerar o relatório PDF
python-telegram-bot — para enviar os alertas




## Stages of development
A Etapa 1 é o parser de logs.

Objetivo: Ler um ficheiro de log Apache/Nginx linha a linha, extrair os campos relevantes com regex, e estruturar os dados em memória para as etapas seguintes poderem trabalhar com eles.

analyzer/parser.py — lógica de parse
samples/access.log — ficheiro de log de exemplo para testes

Lê o ficheiro linha a linha
Aplica uma regex ao formato Combined Log Format (IP - - [timestamp] "METHOD path HTTP" status bytes)
Para cada linha válida devolve um objeto LogEntry com os campos estruturados: IP, timestamp, método HTTP, path, status code, bytes
Linhas malformadas são ignoradas silenciosamente