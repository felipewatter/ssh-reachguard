# Contribuição

Obrigado pelo interesse em aprimorar o SSH ReachGuard. Mantenha todas as discussões e documentos de projeto em PT-BR, mas PRs de código e comentários técnicos em inglês também são aceitos.

## Antes de abrir um pull request

1. Abrir issue com cenário reproduzível e dataset sintético (sem dados de produção).
2. Respeitar as fronteiras de confiança: sem rede, sem execução de comandos, sem permissões por inferência de opção desconhecida.
3. Escrever testes que falhem antes da correção e passem depois, inclusive casos adversariais.
4. Executar `python -m unittest discover -s tests -v`, `python -m compileall -q src tests scripts` e `python scripts/package.py`.
5. Atualizar README/SEMANTICS/RULES para novos recursos ou ajustes de semântica.

## Release

CI pinada por SHA e matriz Ubuntu/Windows, Python 3.11/3.13. O release `v1.0.0` só é criado na branch principal depois da matriz aprovada. Não sobrescrever releases existentes.

## Conduta

Tratar colaboradores com respeito; reportar vulnerabilidades privadamente conforme SECURITY.md. Não publicar credenciais ou inventários de produção.
