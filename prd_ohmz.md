# PRD - Escaner de Rede de Alta Performance em Zig (OhmZ)

## 1. Visao Geral do Produto
O **OhmZ** e um escaner de rede de alta performance e baixa pegada de memoria escrito inteiramente em Zig. Ele foi projetado para superar as limitacoes de concorrencia e seguranca de memoria encontradas em ferramentas legadas em C/C++ (como Nmap e Masscan), utilizando *Raw Sockets* assincronos e o sistema de alocacao explicita de memoria do Zig para garantir velocidade maxima de envio de pacotes sem vazamento de recursos.

### 1.1 Objetivos Principais
* **Velocidade Bruta:** Escanear redes massivas (classe B/A) em minutos, operando de forma assincrona e stateless.
* **Seguranca de Memoria:** Eliminar riscos classicos de corrupcao de memoria (buffer overflow) comuns em ferramentas em C.
* **Portabilidade Total:** Gerar binarios estaticos unicos sem dependencias externas via compilacao cruzada nativa do Zig.
* **Extensibilidade:** Arquitetura modular que permita adicionar novos tipos de scan, protocolos e formatos de saida sem alterar o core.
* **Interoperabilidade:** Formatos de saida compativeis com o ecossistema existente (nmap XML, grepable) para integracao imediata com ferramentas ja adotadas.

### 1.2 Diferenciais Competitivos vs. Nmap e Masscan

| Aspecto | Nmap | Masscan | OhmZ |
|---|---|---|---|
| Linguagem | C/C++ (manual malloc) | C (manual malloc) | Zig (allocators explicitos, deteccao de leaks em dev) |
| Modelo de scan | Stateful (tabela de conexoes) | Stateless (SYN cookies) | Stateless (SYN cookies via comptime hash) |
| Concorrencia | pthreads manual | 1 tx + 1 rx por NIC | io_uring + threads Zig (sem libc) |
| Binario | ~4MB + deps (libpcap, lua, openssl) | ~200KB + libpcap | Binario unico estatico, zero deps |
| Extensibilidade | Lua/NSE (620 scripts) | Nenhuma | Plugins comptime + WASM runtime (futuro) |
| IPv6 | Sim (parcial) | Sim (parcial) | Nativo desde o dia 1 |

---

## 2. Requisitos Funcionais e Arquitetura

### 2.1 Modulo de Geracao de Pacotes (Packet Engine)
* O sistema deve montar cabecalhos IP e TCP/UDP/ICMP/SCTP manualmente em estruturas nativas do Zig usando `packed struct`.
* O sistema deve disparar pacotes sem aguardar a resposta da camada de transporte (modelo assincrono stateless).
* Os pacotes devem ser construidos a partir de **templates pre-compilados** (inspirado em masscan `templ-pkt.c`): um template base e calculado uma vez e cada pacote sofre apenas patch dos campos variaveis (IP destino, porta, seq number), evitando reconstrucao completa por pacote.
* Suporte a multiplos backends de transmissao via interface abstrata:
  - `AF_PACKET` (Linux, modo padrao)
  - `io_uring` (Linux 5.6+, modo de alta performance)
  - Raw sockets genericos (fallback portavel)
  - PF_RING (opcional, compilacao condicional)

### 2.2 Tipos de Escaneamento

#### 2.2.1 TCP Scans
| Tipo | Flag TCP | Resposta Porta Aberta | Resposta Porta Fechada | Uso Principal |
|---|---|---|---|---|
| SYN (`-sS`) | SYN | SYN-ACK | RST | Scan padrao, rapido e discreto |
| Connect (`-sT`) | Full handshake | Conexao estabelecida | Refused | Fallback sem privilegios root |
| FIN (`-sF`) | FIN | Nenhuma resposta | RST | Evasao de firewalls stateless |
| XMAS (`-sX`) | FIN+PSH+URG | Nenhuma resposta | RST | Evasao de firewalls stateless |
| NULL (`-sN`) | Nenhuma flag | Nenhuma resposta | RST | Evasao de firewalls stateless |
| ACK (`-sA`) | ACK | RST (unfiltered) | Sem resposta (filtered) | Mapeamento de regras de firewall |
| Window (`-sW`) | ACK | RST (window > 0) | RST (window = 0) | Variante do ACK scan |

#### 2.2.2 UDP Scan (`-sU`)
* Envio de datagramas UDP vazios ou com payloads especificos por protocolo (DNS, SNMP, NTP, DHCP).
* Porta aberta: resposta UDP. Porta fechada: ICMP Port Unreachable.
* Rate-limiting de ICMP Unreachable tratado com retransmissao adaptativa.

#### 2.2.3 SCTP Scans
* INIT scan (`-sY`): analogo ao SYN scan para o protocolo SCTP.
* COOKIE-ECHO scan (`-sZ`): evasao de firewalls que filtram apenas INIT.

#### 2.2.4 IP Protocol Scan (`-sO`)
* Enumera quais protocolos IP (TCP, UDP, ICMP, SCTP, GRE, etc.) um host suporta.

### 2.3 Modulo de Captura (Listener Engine)
* Uma thread dedicada por interface de rede deve escutar respostas filtrando por tipo de scan ativo.
* **Validacao stateless via SYN cookies**: o numero de sequencia TCP (ISN) e gerado usando SipHash-2-4 sobre `(src_ip, src_port, dst_ip, dst_port, entropy_seed)`. Ao receber SYN-ACK, o cookie e recalculado para validar que a resposta pertence ao scan atual - sem tabela de estado.
* Deduplicacao de respostas via bloom filter ou hash table com TTL curto para evitar contagem dupla de portas abertas.
* O processamento de respostas nao deve bloquear o loop de envio de pacotes.

### 2.4 Descoberta de Hosts (Host Discovery)
Antes do scan de portas, o OhmZ deve determinar quais hosts estao ativos para evitar desperdicio de pacotes em IPs inativos.

| Metodo | Protocolo | Quando Usar |
|---|---|---|
| ARP Ping (`-PR`) | ARP | Rede local (Layer 2) - mais confiavel em LAN |
| ICMP Echo (`-PE`) | ICMP tipo 8 | Descoberta generica |
| ICMP Timestamp (`-PP`) | ICMP tipo 13 | Quando echo e bloqueado por firewall |
| TCP SYN Ping (`-PS`) | TCP SYN para portas comuns | Hosts atras de firewall que bloqueia ICMP |
| TCP ACK Ping (`-PA`) | TCP ACK para portas comuns | Evasao de firewalls stateless |
| UDP Ping (`-PU`) | UDP para porta fechada esperando ICMP Unreachable | Hosts que bloqueiam TCP e ICMP |
| IPv6 Neighbor Discovery | ICMPv6 ND | Redes IPv6 locais |

* Flag `-Pn` para desabilitar discovery e assumir todos os hosts como ativos (modo masscan).
* Portas padrao para TCP ping: 80, 443. Configuravel via `--discovery-ports`.

### 2.5 Randomizacao de Alvos (Target Shuffling)
* Implementacao de cifra **BlackRock** (rede de Feistel com SipHash) para permutar o espaco `(IP x porta)` sem armazenar a permutacao em memoria.
* Garante que cada alvo seja visitado **exatamente uma vez** em ordem pseudo-aleatoria.
* Evita sobrecarregar uma unica sub-rede com rajadas de pacotes (distribuicao uniforme no espaco de alvos).
* A permutacao e baseada em indice, habilitando:
  - **Resume**: salvar o indice atual e continuar de onde parou.
  - **Sharding**: `--shard 1/4` para distribuir o scan entre N maquinas, cada uma cobrindo 1/N do espaco sem sobreposicao.

### 2.6 Banner Grabbing e Deteccao de Servicos
Apos identificar portas abertas, o OhmZ deve opcionalmente coletar banners para identificar servicos e versoes.

#### 2.6.1 Fase 1 - Banner Grabbing Passivo (stateless)
* Ao receber SYN-ACK, completar o handshake e capturar os primeiros bytes de resposta do servico.
* Aplicar pattern matching para identificar protocolo (HTTP, SSH, FTP, SMTP, etc.).

#### 2.6.2 Fase 2 - Probing Ativo (stateful, opcional)
* Enviar probes especificos por protocolo para extrair informacoes detalhadas:

| Protocolo | Probe | Informacao Extraida |
|---|---|---|
| HTTP | `GET / HTTP/1.1\r\n` | Server header, status code, redirect |
| SSH | (banner automatico) | Versao OpenSSH, algoritmos |
| TLS/SSL | ClientHello | Versao TLS, cipher suites, certificado (CN, SAN, expiracao) |
| SMB | Negotiate Protocol | Versao SMB, hostname, dominio |
| FTP | (banner automatico) | Versao do servidor FTP |
| SMTP | (banner automatico) | MTA, versao, EHLO capabilities |
| DNS | Query version.bind | Versao do servidor DNS |
| MySQL | (banner automatico) | Versao MySQL, capabilities |
| Redis | `INFO\r\n` | Versao, memoria, auth status |
| RDP | x224 Connection Request | Suporte a NLA, versao |

* Parsers implementados como state machines em Zig (inspirado no `proto-banner1.c` do masscan), usando comptime para gerar o automato de matching.

### 2.7 OS Fingerprinting (Fase Futura)
* Enviar probes TCP/IP especificos e analisar variacoes no stack de rede para identificar o sistema operacional.
* Sinais analisados: TCP window size, TTL, DF bit, opcoes TCP (MSS, window scale, SACK, timestamps), resposta a pacotes malformados.
* Base de dados de fingerprints em formato estruturado (Zig struct embarcado via comptime).
* Marcado como **Fase 2** do roadmap - depende de uma base de fingerprints curada.

### 2.8 Gerenciamento de Memoria
* Uso estrito de `std.heap.GeneralPurposeAllocator` para deteccao de vazamentos em modo de desenvolvimento.
* Uso de buffers pre-alocados (`FixedBufferAllocator`) no loop critico de envio para garantir latencia zero de alocacao.
* Arena allocator para resultados de scan (alocacao em bloco, liberacao unica no final).
* **Zero alocacoes no hot path**: o loop de transmissao opera exclusivamente sobre buffers pre-alocados e templates de pacote.

### 2.9 Controle de Taxa (Rate Engine)
Inspirado no throttle do masscan, com melhorias:

* **Sliding window de 256 buckets**: mede a taxa real vs. taxa alvo a cada lote de pacotes.
* **Batch sizing adaptativo**: tamanho do lote cresce 0.5% por iteracao e reduz 0.1% quando ultrapassa o alvo - evita overhead de controle por pacote.
* **Deteccao de suspensao**: se o gap entre iteracoes excede 1 segundo, o rate limiter reseta para evitar rajada de compensacao.
* **Timing Templates** (inspirado no nmap):

| Template | Nome | Rate Padrao | Uso |
|---|---|---|---|
| `-T0` | Paranoid | 1 pps | IDS evasion, scan ultra lento |
| `-T1` | Sneaky | 10 pps | IDS evasion |
| `-T2` | Polite | 100 pps | Reducao de carga na rede |
| `-T3` | Normal | 1.000 pps | Padrao |
| `-T4` | Aggressive | 10.000 pps | Redes rapidas, tolerante a perda |
| `-T5` | Insane | 100.000+ pps | Rede local gigabit |

* Flag `--rate <pps>` para override manual do template.
* Flag `--max-retries <n>` para retransmissao de probes sem resposta (padrao: 2).

### 2.10 Tecnicas de Evasao
Para cenarios autorizados de pentest, o OhmZ deve suportar tecnicas que dificultem a deteccao por IDS/IPS:

| Tecnica | Flag | Descricao |
|---|---|---|
| Decoy IPs | `--decoys <ip1,ip2,...>` | Mistura pacotes reais com pacotes de IPs falsos |
| Fragmentacao IP | `--mtu <bytes>` | Fragmenta pacotes para evadir inspetores de payload |
| Source Port Pinning | `--source-port <port>` | Fixa porta de origem (ex: 53 para simular DNS) |
| TTL Manipulation | `--ttl <value>` | Define TTL personalizado para evadir traceroute-based IDS |
| Spoofed Source IP | `--spoof-ip <ip>` | Usa IP de origem falso (requer modo decoy ou idle scan) |
| Idle/Zombie Scan | `--idle-scan <zombie_ip>` | Usa um host "zumbi" para scan indireto sem expor IP real |
| Scan Delay | `--scan-delay <ms>` | Atraso entre probes para evadir deteccao temporal |

### 2.11 Exclusao de Alvos
* `--exclude <ip/cidr>`: exclui hosts ou redes do scan.
* `--excludefile <arquivo>`: carrega lista de exclusao de um arquivo (um CIDR por linha).
* Por padrao, o OhmZ deve excluir enderecos de broadcast, loopback e link-local.
* Enderecos RFC 1918 internos devem gerar warning se `--allow-private` nao estiver presente quando o scan parte de uma interface publica.

---

## 3. Historias de Usuario (User Stories)

### US01: Escaneamento Assincrono Ultra Rapido (Port Scan)
**Como um** analista de seguranca (Pentester)
**Quero** realizar um escaneamento de portas TCP SYN enviando pacotes de forma assincrona
**Para que** eu possa mapear grandes faixas de IP no menor tempo possivel sem gargalos no sistema operacional.

**Criterios de Aceite:**
- [ ] O sistema deve aceitar um IP alvo ou uma faixa CIDR (ex: `192.168.1.0/24`).
- [ ] O sistema deve aceitar multiplas faixas CIDR e listas de alvos via arquivo (`-iL targets.txt`).
- [ ] O envio de pacotes TCP SYN deve ser feito via Raw Sockets sem estabelecer o handshake completo.
- [ ] A taxa de pacotes por segundo (pps) deve ser configuravel via `--rate` ou timing template (`-T0` a `-T5`).
- [ ] A validacao de respostas deve usar SYN cookies (sem tabela de estado por conexao).
- [ ] A ordem de escaneamento deve ser randomizada via cifra BlackRock para distribuir carga uniformemente.

### US02: Captura de Respostas em Thread Separada
**Como um** engenheiro de redes
**Quero** que as respostas dos pacotes enviados sejam capturadas por uma thread dedicada
**Para que** o fluxo de envio nao seja interrompido ou lentificado pelas respostas da rede.

**Criterios de Aceite:**
- [ ] O sistema deve iniciar a thread de escuta antes de comecar o envio dos pacotes.
- [ ] Ao receber um pacote `SYN-ACK`, a ferramenta deve validar o cookie e registrar a porta como "Aberta".
- [ ] Respostas duplicadas devem ser filtradas (deduplicacao via bloom filter).
- [ ] O buffer de recepcao deve ignorar pacotes que nao pertencam a sessao atual de escaneamento.
- [ ] Em modo multi-NIC, cada interface deve ter seu par tx/rx de threads.

### US03: Compilacao Cruzada e Executavel Estatico
**Como um** operador de Red Team
**Quero** compilar a ferramenta em Zig para diferentes arquiteturas com um unico comando
**Para que** eu possa rodar o escaner em dispositivos restritos (roteadores, IoT) sem instalar dependencias.

**Criterios de Aceite:**
- [ ] O arquivo `build.zig` deve gerar um binario 100% estatico (sem link dinamico com `libc`, a menos que explicitamente solicitado).
- [ ] Targets suportados: `x86_64-linux`, `aarch64-linux`, `x86_64-windows`, `arm-linux` (mips futuro).
- [ ] O tamanho do binario final em modo release (`-O ReleaseSafe` ou `-O ReleaseSmall`) deve ser inferior a 5MB.
- [ ] O binario deve detectar automaticamente o backend de transmissao disponivel no runtime (io_uring > AF_PACKET > raw socket).

### US04: Output Multi-Formato
**Como um** desenvolvedor de ferramentas de automacao
**Quero** exportar o resultado do escaneamento em multiplos formatos estruturados
**Para que** eu possa integrar a saida do OhmZ com ferramentas existentes e pipelines de automacao.

**Criterios de Aceite:**
- [ ] `-oJ <arquivo>`: JSON (formato OhmZ nativo).
- [ ] `-oX <arquivo>`: XML compativel com o schema nmap para integracao com ferramentas que consomem nmap XML (Metasploit, OpenVAS, etc.).
- [ ] `-oG <arquivo>`: Grepable - uma linha por host, parseable com grep/awk/cut.
- [ ] `-oN <arquivo>`: NDJSON (newline-delimited JSON) para streaming e ingestao em tempo real (Elasticsearch, jq).
- [ ] `-oB <arquivo>`: Binario compacto (formato proprietario) para scans massivos - menor arquivo, leitura rapida.
- [ ] `-oA <prefixo>`: Gera todos os formatos de uma vez com o prefixo dado.
- [ ] Todos os formatos devem incluir: IP, porta, protocolo, status (open/closed/filtered), servico detectado (se banner grabbing ativo), timestamp, e latencia RTT.

### US05: Descoberta de Hosts (Host Discovery)
**Como um** administrador de rede
**Quero** descobrir quais hosts estao ativos em uma rede antes de escanear portas
**Para que** eu nao desperdice tempo e pacotes em IPs inativos.

**Criterios de Aceite:**
- [ ] O sistema deve suportar ARP ping para redes locais (deteccao automatica por subnet).
- [ ] O sistema deve suportar ICMP echo, TCP SYN ping e TCP ACK ping.
- [ ] Flag `-Pn` desabilita discovery e trata todos os hosts como ativos.
- [ ] Flag `--discovery-ports <portas>` configura portas para TCP ping (padrao: 80,443).
- [ ] O resultado do discovery deve ser emitido separadamente se solicitado (`--discovery-only`).

### US06: Banner Grabbing e Deteccao de Servicos
**Como um** pentester
**Quero** identificar os servicos e versoes rodando nas portas abertas
**Para que** eu possa correlacionar com vulnerabilidades conhecidas (CVEs).

**Criterios de Aceite:**
- [ ] Flag `-sV` ativa banner grabbing apos o scan de portas.
- [ ] O sistema deve coletar banners dos protocolos mais comuns: HTTP, SSH, TLS, FTP, SMTP, SMB, DNS, MySQL, Redis, RDP.
- [ ] Certificados TLS devem ter CN, SAN e data de expiracao extraidos.
- [ ] O resultado deve incluir campo `service` e `version` no output.
- [ ] Banner grabbing deve respeitar o rate limit global e nao degradar a performance do scan de portas.

### US07: Multiplos Tipos de Scan
**Como um** pentester avancado
**Quero** escolher entre diferentes tipos de scan TCP (SYN, FIN, XMAS, NULL, ACK) e UDP
**Para que** eu possa adaptar minha abordagem conforme as defesas do alvo (firewalls, IDS).

**Criterios de Aceite:**
- [ ] Flags `-sS`, `-sF`, `-sX`, `-sN`, `-sA`, `-sW` para cada tipo de scan TCP.
- [ ] Flag `-sU` para UDP scan com payloads especificos por protocolo.
- [ ] Flag `-sT` para TCP connect scan (nao requer root).
- [ ] Flag `-sY` para SCTP INIT scan.
- [ ] Scans combinados: `-sSU` para rodar TCP SYN e UDP simultaneamente.
- [ ] O tipo de scan padrao deve ser SYN (`-sS`) quando executado como root, e Connect (`-sT`) caso contrario.

### US08: Resume e Pause
**Como um** operador que escaneia redes classe A (milhoes de IPs)
**Quero** pausar o scan e retoma-lo posteriormente de onde parou
**Para que** eu nao perca progresso em scans de longa duracao.

**Criterios de Aceite:**
- [ ] Ao receber SIGINT (Ctrl+C), o sistema deve salvar o estado em `ohmz-resume.json`.
- [ ] O estado salvo deve incluir: indice BlackRock atual, configuracao completa, resultados parciais (referencia ao arquivo de output).
- [ ] Flag `--resume <arquivo>` deve retomar o scan exatamente do ponto de parada.
- [ ] Um segundo SIGINT durante o salvamento deve forcar a saida imediata.

### US09: Escaneamento Distribuido (Sharding)
**Como um** operador de infraestrutura de seguranca
**Quero** dividir um scan massivo entre multiplas maquinas
**Para que** eu possa escanear a internet inteira em tempo viavel.

**Criterios de Aceite:**
- [ ] Flag `--shard <N>/<total>` divide o espaco de alvos em `total` partes iguais e executa apenas a parte `N`.
- [ ] A divisao deve ser deterministica: a mesma seed + shard config sempre produz o mesmo subconjunto.
- [ ] Nenhuma sobreposicao entre shards e nenhum alvo deve ser omitido.
- [ ] Os resultados de multiplos shards devem ser mergeaveis via `ohmz merge <file1> <file2> ... -o merged.json`.

### US10: Evasao de IDS/Firewall
**Como um** pentester autorizado
**Quero** usar tecnicas de evasao para contornar firewalls e IDS
**Para que** meu scan represente um teste realista das defesas do alvo.

**Criterios de Aceite:**
- [ ] `--decoys <ip1,ip2,...,ME,...>`: injeta pacotes de IPs decoy junto com os reais.
- [ ] `--mtu <bytes>`: fragmenta pacotes IP no tamanho especificado.
- [ ] `--source-port <port>`: fixa porta de origem.
- [ ] `--scan-delay <ms>`: atraso minimo entre probes para o mesmo host.
- [ ] `--ttl <value>`: define TTL personalizado.
- [ ] Tecnicas de evasao devem funcionar combinadas entre si.

### US11: Suporte a IPv6
**Como um** engenheiro de rede que gerencia infraestrutura dual-stack
**Quero** escanear hosts e redes IPv6
**Para que** eu tenha visibilidade completa de todos os ativos, independente da versao do protocolo IP.

**Criterios de Aceite:**
- [ ] O sistema deve aceitar enderecos IPv6 e notacao CIDR IPv6 (ex: `2001:db8::/32`).
- [ ] Todos os tipos de scan TCP/UDP devem funcionar sobre IPv6.
- [ ] Host discovery deve suportar ICMPv6 Neighbor Discovery para redes locais.
- [ ] SYN cookies devem incluir enderecos IPv6 na geracao do hash.
- [ ] Output deve distinguir claramente entre resultados IPv4 e IPv6.

---

## 4. Requisitos Nao-Funcionais (RNF)

### 4.1 Performance
* Capacidade de gerar pelo menos **100.000 pacotes por segundo** (pps) em hardware padrao de rede gigabit com `AF_PACKET`.
* Com `io_uring`, alvo de **500.000+ pps** em hardware adequado.
* Latencia de processamento por pacote no hot path: < 1 microsegundo.
* Consumo de memoria: < 50MB de RSS para scan de rede /16 (65.536 hosts) com todas as portas.
* O throttle engine deve manter a taxa real dentro de +/- 5% do alvo configurado.

### 4.2 Seguranca
* O codigo deve compilar sem nenhum aviso (warnings) em modo `ReleaseSafe`.
* Testes de concorrencia devem passar sem *race conditions* (verificado com ThreadSanitizer via C interop em CI).
* Nenhum uso de `@ptrCast` ou `@intToPtr` fora de modulos de baixo nivel explicitamente marcados.
* Todas as entradas de usuario (CIDR, portas, arquivos) devem ser validadas antes do uso.

### 4.3 Compatibilidade
* **Tier 1 (totalmente suportado):** Linux x86_64 (Kernel 5.0+), Linux aarch64.
* **Tier 2 (funcional, sem io_uring):** Windows x86_64, macOS aarch64 (via BPF).
* **Tier 3 (compilacao cruzada, best effort):** arm-linux-gnueabihf, mips-linux.

### 4.4 Confiabilidade
* Scan de /16 completo deve concluir sem crash em 100% das execucoes de CI.
* Resume deve preservar 100% do progresso - nenhum alvo perdido ou duplicado apos resume.
* O sistema deve tratar gracefully: interface de rede indisponivel, permissao negada para raw sockets, espaco em disco cheio para output.

### 4.5 Observabilidade
* Flag `--stats` exibe metricas em tempo real no stderr: pps atual, pacotes enviados/recebidos, portas abertas encontradas, % completo, tempo estimado restante.
* Metricas internas expostas via contadores atomicos para profiling sem overhead.

---

## 5. Arquitetura de Alto Nivel

```
+------------------------------------------------------------------+
|                         CLI Parser                                |
|  (std.process.args, config file, --resume)                       |
+------------------------------------------------------------------+
         |                    |                    |
         v                    v                    v
+----------------+  +------------------+  +------------------+
| Target Engine  |  |  Rate Engine     |  | Output Engine    |
| - CIDR parser  |  |  - Throttle      |  | - JSON/XML/Grep  |
| - BlackRock    |  |  - Timing (-T)   |  | - NDJSON/Binary  |
| - Exclude list |  |  - Batch sizing  |  | - File rotation  |
| - Sharding     |  |  - Stats         |  | - Merge tool     |
+----------------+  +------------------+  +------------------+
         |                    |
         v                    v
+------------------------------------------------------------------+
|                     Scan Orchestrator                             |
|  (host discovery -> port scan -> banner grab -> output)          |
+------------------------------------------------------------------+
         |                              |
         v                              v
+-------------------+         +-------------------+
| TX Thread(s)      |         | RX Thread(s)      |
| - Template patch  |         | - SYN cookie val  |
| - Evasion logic   |         | - Deduplication   |
| - AF_PACKET /     |         | - Banner capture  |
|   io_uring send   |         | - Protocol parse  |
+-------------------+         +-------------------+
         |                              |
         v                              v
+------------------------------------------------------------------+
|                 Network Adapter Abstraction                       |
|  AF_PACKET | io_uring | Raw Socket | PF_RING                    |
+------------------------------------------------------------------+
```

---

## 6. Interface CLI - Referencia Rapida

```
ohmz [tipo_scan] [opcoes] <alvo(s)>

ALVOS:
  <ip>                    Host unico (192.168.1.1 ou 2001:db8::1)
  <cidr>                  Faixa CIDR (10.0.0.0/8)
  -iL <arquivo>           Lista de alvos (um por linha)
  --exclude <ip/cidr>     Excluir hosts
  --excludefile <arq>     Arquivo de exclusao

TIPOS DE SCAN:
  -sS                     TCP SYN (padrao com root)
  -sT                     TCP Connect (padrao sem root)
  -sU                     UDP
  -sF / -sX / -sN         FIN / XMAS / NULL
  -sA / -sW               ACK / Window
  -sY / -sZ               SCTP INIT / COOKIE-ECHO
  -sO                     IP Protocol scan

DISCOVERY:
  -Pn                     Sem discovery (assume todos ativos)
  -PS / -PA / -PU         TCP SYN / ACK / UDP ping
  -PE / -PP               ICMP Echo / Timestamp
  -PR                     ARP ping (rede local)

PORTAS:
  -p <range>              Portas (ex: -p 22,80,443 ou -p 1-65535)
  --top-ports <n>         As N portas mais comuns

SERVICOS:
  -sV                     Banner grabbing / deteccao de versao

OUTPUT:
  -oJ / -oX / -oG         JSON / XML / Grepable
  -oN / -oB               NDJSON / Binario
  -oA <prefixo>           Todos os formatos

PERFORMANCE:
  --rate <pps>            Taxa de pacotes por segundo
  -T0 a -T5              Timing template (Paranoid a Insane)
  --max-retries <n>       Retransmissoes (padrao: 2)

EVASAO:
  --decoys <ips>          IPs decoy
  --mtu <bytes>           Fragmentacao
  --source-port <p>       Porta de origem fixa
  --scan-delay <ms>       Atraso entre probes
  --ttl <n>               TTL personalizado

DISTRIBUIDO:
  --shard <N>/<total>     Sharding deterministico
  --resume <arquivo>      Retomar scan interrompido

RUNTIME:
  --stats                 Metricas em tempo real no stderr
  -v / -vv / -vvv         Niveis de verbosidade
  -6                      Forcar modo IPv6
```

---

## 7. Roadmap de Fases

### Fase 1 - Core Engine (MVP)
* [P0] TCP SYN scan com raw sockets e SYN cookies
* [P0] CIDR parser e target randomization (BlackRock)
* [P0] Rate engine com throttle e `--rate`
* [P0] Thread separada TX/RX
* [P0] Output JSON e texto
* [P0] CLI parser basico
* [P0] Compilacao estatica Linux x86_64/aarch64

### Fase 2 - Paridade Funcional
* [P1] Demais tipos de scan TCP (FIN, XMAS, NULL, ACK, Window, Connect)
* [P1] UDP scan com payloads por protocolo
* [P1] Host discovery (ARP, ICMP, TCP ping)
* [P1] Output XML (compativel nmap), grepable, NDJSON, binario
* [P1] Resume/pause com estado persistido
* [P1] Timing templates (-T0 a -T5)
* [P1] Exclude lists
* [P1] Stats em tempo real

### Fase 3 - Inteligencia
* [P2] Banner grabbing e deteccao de servicos (-sV)
* [P2] Parsers de protocolo (HTTP, SSH, TLS, SMB, FTP, SMTP, DNS, MySQL, Redis, RDP)
* [P2] Extracao de certificados TLS
* [P2] Suporte IPv6 completo
* [P2] Sharding distribuido

### Fase 4 - Avancado
* [P3] OS fingerprinting
* [P3] Tecnicas de evasao (decoys, fragmentacao, idle scan)
* [P3] SCTP scans
* [P3] Compilacao cruzada Windows e macOS
* [P3] io_uring backend de alta performance
* [P3] Plugin system (comptime modules + WASM futuro)
* [P3] Multi-NIC com threads dedicadas por adapter

---

## 8. Metricas de Sucesso

| Metrica | Alvo | Como Medir |
|---|---|---|
| Throughput SYN scan | >= 100K pps (AF_PACKET), >= 500K pps (io_uring) | Benchmark em rede isolada com `iperf3` para validar link |
| Memoria RSS | < 50MB para /16 full port | `valgrind --tool=massif` ou `/proc/self/status` |
| Tamanho binario | < 5MB (ReleaseSmall) | `ls -la` do artefato de CI |
| Acuracia | 0 falso-negativo vs. nmap em rede controlada | Comparacao automatizada de output XML |
| Tempo de scan /24 (top 1000 portas) | < 5 segundos em rede local | Benchmark automatizado em CI |
| Resume fidelidade | 0 alvos perdidos ou duplicados | Teste: scan /16, kill em 50%, resume, diff total vs. completo |
