<div align="center">

# SSH ReachGuard

### Auditoria offline de alcance de chaves SSH, exposição de contas e regressões de acesso

[![CI](https://github.com/felipewatter/ssh-reachguard/actions/workflows/ci.yml/badge.svg)](https://github.com/felipewatter/ssh-reachguard/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/Python-3.11%2B-3776AB)](pyproject.toml)
[![Licença MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![SARIF 2.1.0](https://img.shields.io/badge/SARIF-2.1.0-8A2BE2)](docs/ARCHITECTURE.md)
[![Offline](https://img.shields.io/badge/network-offline-informational)](docs/THREAT_MODEL.md)

**[English documentation](README.en.md) · [Arquitetura](docs/ARCHITECTURE.md) · [Semântica e limites](docs/SEMANTICS.md) · [Controles](docs/RULES.md) · [Modelo de ameaças](docs/THREAT_MODEL.md) · [Validação](docs/VALIDATION.md)**

Desenvolvido por [Felipe Silva](https://github.com/felipewatter) · Versão **1.0.0**

</div>

> **Escopo de segurança.** O SSH ReachGuard analisa *snapshots declarativos* e offline de inventários de chaves públicas no formato `authorized_keys`. Ele **não** consulta servidores, não lê contas do sistema, não valida o `sshd_config`, não executa comandos e **não** comprova autorização efetiva em uma conexão SSH real. As respostas `ALLOWED IN MODEL` significam *apenas* que os dados e regras explícitas do modelo permitiriam a tentativa; a posse da chave privada, os controles de `sshd`, certificados, revogações, PAM e autenticação adicional não são verificados.

## 1. Por que este projeto existe?

É comum que uma chave pública seja copiada para múltiplos servidores, que um colaborador deixe uma conta ativa após o desligamento, ou que alterações de manutenção retirem restrições de origem e de encaminhamento. Uma revisão manual de dezenas de arquivos `authorized_keys` pode não responder facilmente a perguntas importantes:

- **Qual identidade consegue alcançar a conta `root` de um host crítico a partir de determinado IP?**
- **Uma nova versão do inventário passou a autorizar tentativas antes negadas?**
- **Quais chaves continuam autorizadas apesar de terem proprietário desativado?**
- **Onde uma mesma chave está reutilizada por contas e servidores distintos?**
- **O bloqueio de `port forwarding`, PTY e shell permanece válido depois de uma mudança?**
- **As evidências podem ser consumidas por uma pipeline sem expor o material da chave?**

O SSH ReachGuard combina análise de chaves públicas, inventário de proprietário, simulação de decisões e testes de regressão, com saída estruturada e códigos de falha definidos.

### Posicionamento frente a projetos existentes

O conhecido [jtesta/ssh-audit](https://github.com/jtesta/ssh-audit) avalia a configuração criptográfica de clientes/servidores e opções de hardening. O SSH ReachGuard **não concorre nesse escopo**: analisa snapshots locais de autorização por chave pública e sua exposição declarativa. Também não é um gerenciador de segredos, PAM, bastion host ou scanner de rede.

Esta é uma ferramenta de *security engineering*, análise de menor privilégio e preparação de change reviews. Não é uma recomendação para depender exclusivamente de um modelo offline antes de conceder acesso real.

## 2. Recursos implementados

| Componente | Comportamento real | Limite explícito |
|---|---|---|
| Parser `authorized_keys` | Chaves Ed25519, RSA, ECDSA P-256/384/521 e FIDO Ed25519; valida campos SSH e canonicalidade base64 | Validação estrutural, não verifica assinaturas nem prova que chave pública é matematicamente válida |
| Fingerprints | SHA-256 sobre o blob binário no formato SSH, com prefixo `SHA256:` | Sem impressão do blob da chave nos relatórios |
| Inventário | Proprietários ativos/desativados, hosts críticos, contas e linhas autorizadas | Dados fornecidos por JSON; não faz coleta remota |
| Restrições de chave | `restrict`, desativações/reabilitações explícitas de PTY/forwarding/`user-rc`, `command=`, `from=` IP/CIDR e `expiry-time=` UTC | Opções desconhecidas são rejeitadas; sem DNS, SSH CA ou outras semânticas de `sshd` |
| Simulador de autorização | IP de origem, identidade, host, conta, modo SSH, horário e motivo da decisão | Resposta **apenas no modelo** |
| Auditoria de postura | 12 regras versionadas `SRG001` a `SRG012`, severidades, IDs estáveis | Sinais de risco; não comprova vulnerabilidade ou exploração |
| Comparação | Achados novos/resolvidos/persistentes; acesso introduzido/removido em matriz explícita | **Não** exaure o espaço de IPs/contas/modos; é preciso cobrir as hipóteses relevantes |
| Gate CI/CD | `--fail-on` e bloqueio **sempre** que a matriz demonstrar introdução de acesso | Não aplica alterações em servidores |
| Relatórios | Texto, JSON e SARIF 2.1.0; saída sem blob e sem comentários de chaves | Nomes de servidores/contas e fingerprints ainda são metadados sensíveis |
| Higiene da entrada | JSON estrito, sem duplicatas, tamanhos limitados, rejeição de symlink, sem rede | Não é um sandbox para execução de scripts arbitrários |
| Testes e distribuição | `unittest`, empacotamento reproduzível, checksum SHA-256, CI Ubuntu/Windows | Sem auditoria independente |

**Dependências de execução:** apenas a biblioteca padrão do Python 3.11+. O gerador opcional de exemplos usa `cryptography` para produzir chaves públicas novas e não é necessário para instalar, operar nem testar o projeto.

## 3. Comece em 60 segundos

### Instalação

```bash
git clone https://github.com/felipewatter/ssh-reachguard.git
cd ssh-reachguard
python -m pip install -e .
sshreachguard --version
```

Também é possível executar sem instalar, a partir da raiz do repositório:

```bash
PYTHONPATH=src python -m ssh_reachguard --version
```

PowerShell:

```powershell
$env:PYTHONPATH = 'src'
python -m ssh_reachguard --version
```

Use o nome do módulo `ssh_reachguard` com `_` no `python -m` e o comando instalado `sshreachguard` sem separadores.

### Auditar o cenário seguro de exemplo

```bash
sshreachguard audit --fleet examples/baseline.json \
  --at 2026-11-10T12:00:00Z --fail-on high --format text
```

Resultado esperado (resumo):

```text
Hosts=2 accounts=3 entries=3 owners=3
Findings=0 severity={'info': 0, 'low': 0, 'medium': 0, 'high': 0, 'critical': 0}
```

### Auditar um cenário que deve ser bloqueado

```bash
sshreachguard audit --fleet examples/candidate-risky.json \
  --at 2026-11-10T12:00:00Z --fail-on high
```

**Código de saída 1**: risco no limiar definido. O exemplo contém `root` com uma chave sem restrições, um acesso ampliado de IP externo, uma chave sem proprietário e um usuário desativado ainda autorizado.

### Verificar uma tentativa específica

```bash
sshreachguard explain --fleet examples/baseline.json \
  --query examples/query.json --at 2026-11-10T12:00:00Z --format json
```

O arquivo `query.json` pergunta se `ops-backup` poderia se autenticar como `root` no `bastion-01`, vindo de `198.51.100.15`. A resposta esperada é `allowed_in_model: false`, pois o exemplo restringe a origem a `10.20.0.0/16`.

### Executar uma matriz de asserções

```bash
sshreachguard assert --fleet examples/baseline.json \
  --queries examples/queries.json --at 2026-11-10T12:00:00Z
```

Resultado esperado: **6/6 asserções aprovadas**.

### Comparar configurações antes de uma mudança

```bash
sshreachguard compare --baseline examples/baseline.json \
  --candidate examples/candidate-risky.json \
  --queries examples/queries.json --at 2026-11-10T12:00:00Z \
  --fail-on high --output compare-report.json --sarif compare-report.sarif
```

Resultado esperado: **2 hipóteses de acesso introduzido** na matriz e novos riscos. O comando retorna **1**. Mesmo usando `--fail-on none`, um acesso explicitamente introduzido na matriz **continua bloqueando** a comparação.

**PowerShell:** execute os mesmos comandos em uma única linha; no Windows, `\` não é o caractere de continuação do PowerShell (use crase ``` ` ``` se preferir múltiplas linhas).

## 4. Modelo de dados

O projeto trabalha com três coleções: `owners`, `hosts` e `accounts`. Cada chave pública autorizada aparece como **uma linha completa** de OpenSSH dentro do array `authorized_keys` de uma conta. Cada chave pública pertencente a um `owner` deve aparecer **sem opções**.

Exemplo esquemático, com conteúdo abreviado *apenas para explicação* (não válido como entrada):

```json
{
  "schema": 1,
  "owners": [
    {"id": "backup", "status": "active", "keys": ["ssh-ed25519 <BASE64_DA_CHAVE_PUBLICA>"]}
  ],
  "hosts": [
    {"name": "bastion-01", "critical": true, "accounts": [
      {"name": "root", "authorized_keys": [
        "restrict,from=\"10.20.0.0/16\",command=\"/usr/local/sbin/backup\",expiry-time=\"20271231235959Z\" ssh-ed25519 <BASE64_DA_CHAVE_PUBLICA>"
      ]}
    ]}
  ]
}
```

**Arquivos executáveis válidos:** `examples/baseline.json`, `examples/candidate-risky.json`, `examples/queries.json` e `examples/query.json` contêm **somente chaves públicas de laboratório**, sem credenciais privadas.

As queries do `explain` e da matriz usam:

| Campo | Exemplo | Significado |
|---|---|---|
| `owner` | `ops-backup` | Proprietário declarado da chave pública |
| `host` | `bastion-01` | Host declarado no snapshot |
| `account` | `root` | Conta SSH alvo |
| `source_ip` | `10.20.1.5` | Origem numérica IPv4/IPv6 da tentativa |
| `mode` | `authenticate`, `shell`, `pty`, `tcp-forward`, `agent-forward`, `x11-forward` | Capacidade solicitada no modelo |
| `expect` | `true` / `false` | Expectativa opcional em `explain`, obrigatória em `assert` |

## 5. Decisões, restrições e confiança

**Assumimos para a simulação:** cada proprietário ativo tem posse da chave privada correspondente, o snapshot é completo, e não há restrições adicionais de `sshd`, PAM, chaves revogadas, ACLs ou políticas externas. Essas são hipóteses do modelo, **não fatos verificados**. Se a chave aparece em duas contas diferentes, cada par host/conta é avaliado separadamente. Um proprietário desativado é negado no modelo, mas isso não revoga uma chave fisicamente instalada; a auditoria gera `SRG010` justamente para sinalizar essa diferença.

A verificação `authenticate` só avalia restrições de chave e IP, além de proprietário e expiração. Em `shell`, `command=` bloqueia o shell livre. Em `tcp-forward`, `agent-forward`, `pty` e `x11-forward`, são consultados os controles explícitos da chave. `command=` **não** desativa automaticamente o encaminhamento de portas; é necessário `restrict` ou `no-port-forwarding`.

As restrições `from=` aceitas são deliberadamente **somente IP/CIDR numéricos**, inclusive exclusões `!`. Padrões de hostname, DNS, curingas, certificados de autoridade SSH, assinaturas, revogação e operadores não suportados **geram erro 2** em vez de serem interpretados de forma permissiva. `expiry-time=` exige `YYYYMMDDHHMMSSZ` em UTC para evitar ambiguidades de timezone. Consulte os detalhes em [docs/SEMANTICS.md](docs/SEMANTICS.md).

## 6. Catálogo de regras

| Regra | Condição detectada | Severidade |
|---|---|---|
| `SRG001` | Chave autorizada sem proprietário identificado | Alta |
| `SRG002` | Chave para `root` sem restrições de origem, comando, expiração ou `restrict` | Crítica |
| `SRG003` | Chave de `root` sem limitação de origem | Alta |
| `SRG004` | Chave de `root` permite port forwarding | Alta |
| `SRG005` | Chave de `root` sem comando forçado | Média |
| `SRG006` | Chave de `root` sem prazo de expiração | Média |
| `SRG007` | Chave em host crítico sem limitação de origem | Alta |
| `SRG008` | Chave vencida ainda presente nas autorizações | Média |
| `SRG009` | Mesma chave atribuída a dois ou mais proprietários | Alta |
| `SRG010` | Chave autorizada pertence a proprietário desativado | Alta |
| `SRG011` | Mesma chave repetida na mesma conta | Média |
| `SRG012` | Mesma chave presente em mais hosts que o limite (`--max-hosts`) | Alta |

As severidades expressam **heurísticas de prioridade**, não confirmação de exploração. A condição `SRG012` considera hosts distintos, não usuários ou entradas. [Catálogo detalhado](docs/RULES.md).

## 7. CI/CD e relatórios

A ferramenta funciona como um controle *fail-closed* em uma revisão de acesso. Comandos produzem:

- **0**: consulta/asserções aprovadas ou ausência de achados que ultrapassem o limiar;
- **1**: gate bloqueado, asserção divergente ou ampliação de acesso na matriz;
- **2**: entrada inválida, configuração não suportada, arquivos inseguros ou falha operacional.

A opção `--fail-on none` desativa o bloqueio por severidade em `audit` e por novos achados em `compare`, mas não libera regressões de autorização explícitas. O relatório JSON inclui IDs estáveis derivados de SHA-256, informações estruturadas e evidências mínimas. A opção `--sarif` exporta **SARIF 2.1.0** dos achados, sem acesso à rede. Os arquivos de saída são criados com exclusividade: não são sobrescritos nem são seguidos symlinks existentes.

O workflow `.github/workflows/ci.yml` executa as seguintes validações após push e pull request:

1. Instalação e testes (`unittest`) no **Ubuntu** e **Windows**, versões **Python 3.11 e 3.13**.
2. Compilação de sintaxe, execução do baseline, da matriz e comprovação de falha no cenário inseguro.
3. Empacotamento determinístico, integridade de ZIP e validação contra publicação de materiais privados.
4. No push para `main`, **somente após toda a matriz passar**, geração do release `v1.0.0` com ZIP e arquivo `.sha256`. Se esse release já existir, o job não o substitui.

O badge passa a refletir execução real apenas depois da publicação do repositório e da CI no GitHub.

## 8. Testes locais

```bash
python -m unittest discover -s tests -v
python -m compileall -q src tests scripts
python scripts/package.py
```

O `unittest` cobre parsing, formatos de chaves, restrições, comparações, exposições, schemas, I/O, asserções, relatórios, negação de entradas inválidas e empacotamento. Há um teste adicional que submete centenas de alterações aleatórias reprodutíveis a linhas `authorized_keys` e verifica que nenhum erro inesperado escapou do parser; **não** substitui fuzzing profissional e auditoria externa.

Para repetir em PowerShell (na raiz):

```powershell
$env:PYTHONPATH = 'src'
python -m unittest discover -s tests -v
python -m compileall -q src tests scripts
python scripts/package.py
```

## 9. Segurança, privacidade e limites operacionais

- **Jamais inclua chaves privadas** no inventário. Use somente chaves públicas e datasets sanitizados. Os exemplos do projeto foram gerados sem armazenar chaves privadas.
- Um fingerprint não é uma identidade humana. Um mesmo par de chaves pode ser compartilhado por vários operadores; o mecanismo sinaliza múltiplos proprietários, mas não confirma quem detém a chave privada.
- `SHA256:` identifica os bytes da chave pública, **não** um hash de senha nem um certificado de autenticidade.
- O projeto **não suporta SSH user certificates**, `cert-authority`, `principals=`, `AuthorizedKeysCommand`, extensões, padrões DNS em `from=` ou validação de `sshd_config`/PAM. Tais sistemas podem alterar integralmente o resultado real.
- O modelo não comprova que `root` esteja autorizado a fazer login por SSH (`PermitRootLogin`), nem verifica `AllowUsers`, `AuthenticationMethods`, certificados ou métodos adicionais de autenticação.
- O parser valida campos e comprimentos de chaves públicas; **não** implementa toda a semântica criptográfica da família de chaves SSH nem substitui `ssh-keygen`.
- O programa não recebe comandos para execução, não faz SSH, não abre portas de rede e não remove chaves.
- O arquivo JSON e os relatórios podem conter **metadados operacionais sensíveis**. Restrinja as permissões e não publique inventários de produção.
- Entradas são limitadas a 2 MB, com rejeição de chaves duplicadas em objetos JSON, de links simbólicos e de valores não finitos. Links simbólicos em ancestrais e arquivos finais também são recusados.

Para incidentes, consulte [SECURITY.md](SECURITY.md) e [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

## 10. Estrutura do repositório

```text
ssh-reachguard/
├── .github/
│   ├── workflows/ci.yml
│   └── dependabot.yml
├── src/ssh_reachguard/
│   ├── parser.py        # authorized_keys, SSH wire format e opções
│   ├── engine.py        # modelo, auditoria, decisões e comparação
│   ├── io.py            # JSON seguro, relatórios e SARIF
│   ├── cli.py           # CLI, gates e códigos de saída
│   ├── __init__.py
│   └── __main__.py
├── tests/               # cobertura do parser, motor, CLI e pacote
├── examples/            # inventários e consultas inteiramente sintéticos
├── docs/                # documentação técnica e modelo de ameaças
├── scripts/package.py  # ZIP reproduzível e checksum SHA-256
├── scripts/make_examples.py  # opcional, regenera fixtures públicas
├── pyproject.toml
├── SECURITY.md
├── CONTRIBUTING.md
├── CHANGELOG.md
├── RELEASE_NOTES.md
├── README.en.md
├── README.md
└── LICENSE
```

## 11. Referências e verificação externa

- [OpenSSH `sshd(8)`: `AUTHORIZED_KEYS FILE FORMAT`](https://man.openbsd.org/sshd) — opções de chave e limites da configuração real.
- [OpenSSH `ssh-keygen(1)`](https://man.openbsd.org/ssh-keygen) — fingerprints e formato de chaves públicas.
- [NIST SP 800-53 — Access Control](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final) — princípios gerais de gestão de acesso.
- [GitHub: Reviewing your SSH keys](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/reviewing-your-ssh-keys) — revisão periódica de chaves.
- [SARIF v2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html) — formato interoperável de resultados.

**Contribuições:** veja [CONTRIBUTING.md](CONTRIBUTING.md). **Licença:** [MIT](LICENSE).

**Estado:** versão inicial 1.0.0, projeto de engenharia/estudo, sem auditoria independente. Não use a ausência de findings como prova de segurança de um ambiente real.
