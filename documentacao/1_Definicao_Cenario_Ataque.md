# Definição do Cenário de Ataque

## Empresa
TechStore Ltda. - E-commerce de médio porte

## Infraestrutura
- Servidor web com WordPress
- Banco de dados de clientes
- Rede interna
- Firewall perimetral
- Sistema de autenticação
- Sistema de backup

## Vetor de Ataque
1. **Reconhecimento**
   - Identificação do domínio da empresa
   - Coleta de informações públicas
   - Varredura de portas e serviços

2. **Acesso Inicial**
   - Phishing direcionado a funcionário do departamento financeiro
   - Exploração de vulnerabilidade no WordPress
   - Upload de webshell

3. **Pós-Exploração**
   - Elevação de privilégios
   - Movimento lateral na rede
   - Coleta de credenciais

4. **Exfiltração de Dados**
   - Acesso ao banco de dados
   - Compactação de dados sensíveis
   - Transferência para servidor externo

5. **Impacto**
   - Criptografia de arquivos com ransomware
   - Pedido de resgate em criptomoeda
   - Indisponibilidade de serviços
