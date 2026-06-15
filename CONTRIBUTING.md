# &#129309; Contribuindo para o Agente de Seguranca WiFi

Obrigado por contribuir! Este documento explica como participar do projeto.

---

## &#128221; Como Contribuir

### 1. Fork o Repositorio

Clique no botao "Fork" no GitHub para criar uma copia do repositorio na sua conta.

### 2. Clone seu Fork

```bash
git clone https://github.com/rodrigopdevmt/Agente-de-Seguranca-WiFi---ESP32-C6.git
cd Agente-de-Seguranca-WiFi---ESP32-C6
```

### 3. Crie uma Branch

```bash
git checkout -b feature/nova-funcionalidade
```

Nomenclatura de branches:
- `feature/nome-da-feature` - Novas funcionalidades
- `fix/nome-do-bug` - Correcao de bugs
- `docs/nome-da-doc` - Alteracoes na documentacao
- `refactor/nome-do-refactor` - Refatoracao de codigo

### 4. Faca suas Alteracoes

- Siga o estilo de codigo existente
- Comente em portugues quando necessario
- Mantenha o firmware dentro do limite de flash (1MB)

### 5. Teste

```bash
# Compilar
pio run

# Gravar e monitorar
pio run -t upload && pio device monitor
```

### 6. Commit

```bash
git add .
git commit -m "feat: adiciona funcionalidade X"
```

Convencao de commits:
- `feat:` nova funcionalidade
- `fix:` correcao de bug
- `docs:` documentacao
- `refactor:` refatoracao
- `style:` formatacao
- `test:` testes

### 7. Push e Pull Request

```bash
git push origin feature/nova-funcionalidade
```

Abra um Pull Request no GitHub com descricao detalhada das alteracoes.

---

## &#128295; Regras

### Codigo

- Manter tudo em **portugues** (variaveis, comentarios, dashboard)
- Seguir o estilo de codigo existente
- Nao ultrapassar 95% da flash (1MB)
- Usar ESP-IDF API (nao Arduino)

### Dashboard

- Tema dark com glassmorphism
- Cores: roxo (#6366f1), ciano (#34d399), vermelho (#f87171), amarelo (#fbbf24)
- Fonte: -apple-system, Segoe UI
- Tudo em portugues

### Commits

- Mensagens curtas e descritivas
- Usar convencao conventional commits
- Um commit por funcionalidade

---

## &#128161; Ideias para Contribuicao

- [ ] Modo silencioso anti-ataque (resposta automatica a deauth)
- [ ] Gravacao de trafego em SPIFFS
- [ ] Relatorios com timestamps
- [ ] Suporte a multiplos idiomas
- [ ] Modo noturno / tema claro
- [ ] Notificacoes push
- [ ] Integracao com MQTT
- [ ] OTA (Over-The-Air) updates
- [ ] Testes automatizados

---

## &#128270; Problemas e Sugestoes

Abra uma Issue no GitHub com:

- **Titulo** claro e descritivo
- **Descricao** detalhada do problema ou sugestao
- **Passos** para reproduzir (se for bug)
- **Screenshots** (se aplicavel)
- **Hardware** usado
- **Versao do firmware**

---

## &#128220; Codigo de Conduta

- Respeite todos os participantes
- Seja construtivo nas criticas
- Foque no que e melhor para o projeto
- Ajudem uns aos outros

---

## &#128176; Doacoes

Se este projeto te ajudou, considere fazer uma doacao para apoiar o desenvolvimento.

---

Obrigado por contribuir! &#128737;
