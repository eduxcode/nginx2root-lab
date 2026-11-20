# RCE: o que o laboratório prova, o que é hipótese

Este documento separa **fato reproduzido** de **análise**. Ele não promete
"shell em 30 segundos": o que existe aqui é um primitivo de corrupção de
memória real, reproduzível e instrumentado, mais a discussão honesta do
que falta para transformá-lo em execução de código.

Autor: **eduxcode** — <https://github.com/eduxcode>

---

## 1. O que já está provado

Rodando `./scripts/rce-evidence.sh` (alvo compilado com AddressSanitizer),
a cadeia inteira do CVE-2026-123007 termina assim:

```text
=================================================================
==197362==ERROR: AddressSanitizer: negative-size-param: (size=-1073741824)
    #0 ... in memcpy
    #1 ... in ngx_ssl_send_chain src/event/ngx_event_openssl.c:3150
    #2 ... in ngx_http_v2_send_output_queue src/http/v2/ngx_http_v2.c:557
    #3 ... in ngx_http_v2_write_handler src/http/v2/ngx_http_v2.c:502
    #4 ... in ngx_epoll_process_events src/event/modules/ngx_epoll_module.c:930
    ...
0x... is located 0 bytes inside of 1048576-byte region
allocated by thread T0 here:
    #1 ... in ngx_alloc src/os/unix/ngx_alloc.c:22
    #2 ... in ngx_palloc_large src/core/ngx_palloc.c:220
    #4 ... in ngx_output_chain_get_buf src/core/ngx_output_chain.c:484
    ...
SUMMARY: AddressSanitizer: negative-size-param
         src/event/ngx_event_openssl.c:3150 in ngx_ssl_send_chain
==197362==ABORTING
```

Três informações importantes nesse relatório:

1. **Classe do bug**: `negative-size-param`. Não é ponteiro nulo, não é
   *use-after-free*. É um `memcpy` cujo terceiro argumento é um `ssize_t`
   negativo que, convertido para `size_t`, vira ~`2^64`.
2. **Comprimento controlado pelo atacante**: o valor `-1073741824` é
   exatamente o `send_window` que o cliente fez o nginx acumular
   (`2^64 − 1 GiB`). Mudar o acumulado muda o `size`. O atacante decide
   *quanto* o `memcpy` tenta copiar.
3. **Origem e destino**: o endereço apontado pelo ASAN é o *buffer de
   origem* de 1 MiB, alocado por `ngx_output_chain_get_buf` — o chunk de
   resposta criado por `output_buffers 8 1m`. O destino é
   `c->ssl->buf`, o buffer de escrita TLS (16 KiB por padrão,
   `ssl_buffer_size`).

Sem ASAN, o mesmo caminho termina em `SIGSEGV` dentro de
`ngx_memcpy` (ver `scripts/verify.sh`), com `worker process ... exited on
signal 11`.

---

## 2. Por que isso é corrupção, e não só DoS

Um `memcpy(dst, src, (size_t)-N)` copia **tudo o que estiver mapeado**
entre `dst` e o primeiro endereço não mapeado, e também lê tudo o que
estiver depois de `src`. Ou seja:

```
        dst (SSL buf, 16 KiB)                src (chunk de 1 MiB)
             │                                    │
   ┌─────────▼──────────┬──────────────┬──────────▼──────┬───────────┬──────
   │ buffer TLS         │ heap adjacente│ resposta        │ heap      │ ...
   └────────────────────┴──────────────┴─────────────────┴───────────┴──────
             └────────── copia cresce para a direita ──────────▶
```

* **Bytes escritos além de `dst`**: heap do worker — pools, structs de
  conexão/stream, buffers, cabeçalhos de alocação do glibc.
* **Bytes lidos além de `src`**: o que estiver adjacente ao chunk de
  resposta. Se o atacante conseguir posicionar dados controlados ali
  (corpo de requisição, por exemplo), o transbordamento escreve **bytes
  escolhidos por ele**.
* A cópia só para quando bate em uma página não mapeada (ou somente
  leitura). Aí o worker morre.

É exatamente a definição de *heap buffer overflow* com conteúdo e
comprimento influenciados pelo atacante — o material bruto de um exploit.

O que o ASAN mostra é o instante do primeiro byte fora do allocation.
Sem ASAN, o `memcpy` do glibc (AVX2/AVX-512/ERMS) avança em blocos de
32–64 bytes e só falha na página não mapeada seguinte; dependendo do
heap, isso pode significar vários MiB escritos antes do `SIGSEGV`.

---

## 3. A aritmética do `size`

O valor não é aleatório. Ele nasce em
`ngx_http_v2_send_chain()`:

```c
if (limit == 0 || limit > (off_t) h2c->send_window) {
    limit = h2c->send_window;      /* size_t > 2^63 → off_t negativo */
}
```

e chega em `ngx_ssl_send_chain()`:

```c
send = buf->last - buf->pos;       /* >= 0 */
...
size = in->buf->last - in->buf->pos;

if (size > buf->end - buf->last) {
    size = buf->end - buf->last;
}

if (send + size > limit) {
    size = (ssize_t) (limit - send);   /* fica negativo */
}

ngx_memcpy(buf->last, in->buf->pos, size);   /* size_t ≈ 2^64 */
```

Como `send >= 0` e `limit < 0`, a condição `send + size > limit` é
sempre verdadeira e `size` recebe o `limit` negativo. Não há clamp
posterior. É o ponto sem retorno.

---

## 4. O caminho até o `2^63`: por que ~52 GiB

Para `(off_t) send_window` ficar negativo, o contador precisa passar de
`2^63`. Cada `WINDOW_UPDATE` soma no máximo `2^31 − 1`:

```
2^63 / (2^31 − 1) ≈ 4,29 × 10^9 frames
4,29 × 10^9 × 13 bytes  ≈ 55,8 × 10^9 bytes ≈ 52 GiB
```

Perto de `2^64`, são ~104 GiB. Somando a checagem anti-abuso do nginx
(`h2c->total_bytes / 8 > h2c->payload_bytes + 1048576`) e o corpo
necessário para "pagar" os frames, análises públicas falam em ~119 GiB
de tráfego total.

É por isso que o laboratório tem o **acelerador**: ele substitui apenas
esse trecho (o estado final de 52 GiB de frames) e é anunciado na tela.
Os estágios 1–6 continuam sendo comportamento real do nginx 1.31.8.

---

## 5. O que falta para RCE de verdade

O primitivo existe. A conversão para execução de código é o problema
difícil, e o laboratório **não** a demonstra. Quatro obstáculos reais:

### 5.1 O `memcpy` não pode ser interrompido

A corrupção acontece *dentro* do `memcpy`, e o `SIGSEGV` mata o worker
no mesmo instante. Qualquer struct corrompida no heap do próprio worker
morre junto com ele — não há retorno para "usar" o ponteiro
sobrescrito. Isso derruba a ideia ingênua de "sobrescrever um function
pointer e esperar a chamada".

### 5.2 O comprimento é fixo em ~2^64

Não existe valor de `send_window` negativo que produza uma cópia
"pequena": qualquer negativo vira ~`2^64` em `size_t`. Não há como pedir
"transborde só 64 bytes". O exploit precisa conviver com uma escrita
linear gigante que termina em *page fault*.

### 5.3 O conteúdo depende do heap adjacente

Os primeiros 1 MiB copiados vêm da resposta legítima. Depois disso, o
`memcpy` lê o que estiver depois do chunk de origem. Para escrever um
payload, é preciso *grooming*: fazer o alocador posicionar dados
controlados imediatamente após o buffer de resposta (corpo de
requisição, upload, cabeçalhos grandes) e posicionar um alvo útil
imediatamente após o buffer TLS.

### 5.4 O alvo precisa sobreviver ao fault

Como o worker morre, o alvo corrompido tem que ser consumido:

* por **outro** worker ou pelo master, através de memória compartilhada
  (`ssl_session_cache shared:`, zonas de `limit_req`/`limit_conn`,
  `proxy_cache` em memória);
* por um processo que reinicie e releia um arquivo/mapeamento
  corrompido;
* ou por um `SIGSEGV` handler — que o nginx não instala.

Nenhum desses caminhos foi reproduzido aqui. Análises públicas descrevem
RCE com heap grooming e ~119 GiB; neste laboratório nós paramos no
primitivo, que é o que dá para provar de forma reprodutível em segundos.

---

## 6. Experimentos que ainda valem a pena

Se você quiser continuar a pesquisa (em ambiente isolado):

1. **Medir a janela de escrita**: rodar sem ASAN sob `gdb`, capturar o
   endereço do fault e comparar com `dst`. Isso dá quantos bytes foram
   efetivamente escritos antes da morte.
2. **Grooming do destino**: alocar/free repetidamente buffers de 1 MiB
   (`output_buffers`) para tentar colocar um objeto interessante
   (ex.: `ngx_pool_cleanup_t`, struct de stream) logo após o SSL buffer.
3. **Grooming da origem**: enviar corpo de requisição com padrão
   reconhecível e verificar, no core dump, se ele aparece no fluxo
   copiado.
4. **Memória compartilhada**: mapear zonas compartilhadas e ver se o
   transbordamento alcança uma delas; medir se a corrupção sobrevive ao
   worker.
5. **Variante h2c (sem TLS)**: o caminho é outro (`ngx_writev_chain`),
   provavelmente só `EFAULT`; serve para comparar primitivos.

Cada um desses experimentos exige instrumentação própria e deve ficar
claramente separado do que é "comportamento original do nginx".

---

## 7. Como reproduzir a evidência atual

```bash
cd nginx2root-lab
./scripts/rce-evidence.sh          # build ASAN + ataque + relatório
```

O primeiro build leva 1–2 minutos; depois é instantâneo. A porta usada é
8444 (mude com `N2R_ASAN_PORT=...`).

Para ver o `SIGSEGV` "puro", sem ASAN:

```bash
# terminal 1
N2R_SINGLE=1 ./scripts/native-up.sh
# terminal 2
./scripts/native-attack.sh
```

---

## 8. Leitura defensiva

* O vetor é **remoto e sem autenticação**, mas o custo de tráfego é alto
  (~52 GiB para chegar ao `2^63`, ~119 GiB para o cenário completo).
* O efeito garantido é **negação de serviço** (worker morto, conexão
  derrubada). Qualquer RCE é condicional a grooming e a um alvo que
  sobreviva ao fault.
* A correção (1.31.9 / 1.30.7) elimina o primitivo inteiro; não é caso
  de "só mitigar o crash".
* Enquanto não atualizar: `http2 off;` remove este vetor e o
  CVE-2026-123633, mas não as outras UAFs da mesma leva.
