// SPDX-License-Identifier: 0BSD

const REMOTE_DNS_URL = 'https://raw.githubusercontent.com/yongchengchen/doh/refs/heads/main/localDNS.json'
const CACHE_TTL_MS = 10 * 60 * 1000  // 10分钟

const doh = 'https://security.cloudflare-dns.com/dns-query'
const dohjson = 'https://security.cloudflare-dns.com/dns-query'
const contype = 'application/dns-message'
const jstontype = 'application/dns-json'
const path = ''; // default allow all, must start with '/' if specified, eg. "/dns-query"
const r404 = new Response(null, {status: 404});

let localDNSCache = null
let lastFetchTime = 0

export default {
    async fetch(r, env, ctx) {
        return handleRequest(r, ctx);
    },
};

async function handleRequest(request, ctx) {
    const { method, headers, url } = request
    const {searchParams, pathname} = new URL(url)

    if (pathname === '/purge-cache') {
        localDNSCache = null
        lastFetchTime = 0
        return new Response("Cache purged", { status: 200 })
    }

    if (pathname === '/.well-known/dns-query') {
        return Response.redirect('/dns-query', 301);
    }

    if (!pathname.startsWith(path)) return r404

    // JSON DoH (GET)
    if (method === 'GET' && headers.get('Accept') === jstontype) {
        const name = searchParams.get('name')
        const type = searchParams.get('type') || "A"
        const qname = name?.endsWith('.') ? name : name + '.'

        const dnsMap = await fetchLocalDNS()

        if (dnsMap[qname] && dnsMap[qname][type]) {
        return buildJSONResponse(qname, type, dnsMap[qname][type])
        }

        // fallback
        return fetch(dohjson + '?' + searchParams.toString(), {
        method: 'GET',
        headers: { 'Accept': jstontype }
        })
    }

    // Binary DoH (POST)
    if (method === 'POST' && headers.get('content-type') === contype) {
        const reqBody = await request.arrayBuffer()
        const question = parseDNSQuestion(reqBody)

        if (question) {
        const { name, type } = question
        const qname = name.endsWith('.') ? name : name + '.'
        const dnsMap = await fetchLocalDNS()

        if (dnsMap[qname] && dnsMap[qname][type]) {
            return buildWireFormatResponse(qname, type, dnsMap[qname][type], reqBody)
        }
        }

        return fetch(doh, {
        method: 'POST',
        headers: {
            'Accept': contype,
            'Content-Type': contype
        },
        body: reqBody
        })
    }

    // Binary DoH (GET)
    if (method === 'GET' && searchParams.has('dns')) {
        return fetch(doh + '?dns=' + searchParams.get('dns'), {
        method: 'GET',
        headers: { 'Accept': contype }
        })
    }

    return r404
}


async function fetchLocalDNS(forceReload = false) {
    const now = Date.now()
  
    // 异步后台刷新逻辑
    if (!forceReload && localDNSCache && now - lastFetchTime > CACHE_TTL_MS / 2) {
      lastFetchTime = now // 防止并发
      fetch(REMOTE_DNS_URL).then(async res => {
        if (res.ok) {
          const data = await res.json()
          localDNSCache = data
        }
      }).catch(() => {})
    }
  
    if (!forceReload && localDNSCache && now - lastFetchTime < CACHE_TTL_MS) {
      return localDNSCache
    }
  
    try {
      const res = await fetch(REMOTE_DNS_URL, { cf: { cacheTtl: 0 } })
      if (!res.ok) throw new Error("fetch failed")
      const data = await res.json()
      localDNSCache = data
      lastFetchTime = now
      return localDNSCache
    } catch (e) {
      console.warn("Fetch failed, fallback to stale:", e)
      return localDNSCache || {}
    }
  }

// === helpers ===

function buildJSONResponse(qname, type, data) {
  return new Response(JSON.stringify({
    Status: 0,
    TC: false,
    RD: true,
    RA: true,
    AD: false,
    CD: false,
    Question: [{
      name: qname,
      type: type === 'A' ? 1 : 28
    }],
    Answer: [{
      name: qname,
      type: type === 'A' ? 1 : 28,
      TTL: 60,
      data: data
    }]
  }), {
    headers: { "content-type": jstontype }
  })
}

// Parse binary DNS question (name + type)
// Only supports A and AAAA
function parseDNSQuestion(buf) {
  try {
    const view = new DataView(buf)
    let offset = 12 // skip header

    // parse QNAME
    const labels = []
    while (true) {
      const len = view.getUint8(offset++)
      if (len === 0) break
      const label = new TextDecoder().decode(buf.slice(offset, offset + len))
      labels.push(label)
      offset += len
    }
    const name = labels.join('.') + '.'
    const typeCode = view.getUint16(offset)
    const type = typeCode === 1 ? 'A' : (typeCode === 28 ? 'AAAA' : null)
    return type ? { name, type } : null
  } catch (e) {
    return null
  }
}

// Build minimal DNS wire-format response (only A/AAAA)
function buildWireFormatResponse(name, type, ip, reqBuf) {
  const encoder = new TextEncoder()
  const nameParts = name.split('.')
  const nameBuf = []
  nameParts.forEach(part => {
    const enc = encoder.encode(part)
    nameBuf.push(enc.length)
    nameBuf.push(...enc)
  })
  nameBuf.push(0) // end of name

  const qtype = type === 'A' ? 1 : 28
  const qclass = 1

  const header = new Uint8Array(reqBuf.slice(0, 12)) // copy ID and flags
  header[2] = 0x81 // QR=1, Opcode=0, AA=0, TC=0, RD=1
  header[3] = 0x80 // RA=1, Z=0, RCODE=0

  header[4] = 0; header[5] = 1  // QDCOUNT
  header[6] = 0; header[7] = 1  // ANCOUNT
  header[8] = 0; header[9] = 0
  header[10] = 0; header[11] = 0

  const question = new Uint8Array([
    ...nameBuf,
    0x00, qtype,
    0x00, qclass
  ])

  const rdata = type === 'A'
    ? ip.split('.').map(s => parseInt(s))
    : ip.split(':').flatMap(h => {
        const padded = h.padStart(4, '0')
        return [parseInt(padded.slice(0, 2), 16), parseInt(padded.slice(2), 16)]
      })

  const answer = new Uint8Array([
    ...nameBuf,
    0x00, qtype,
    0x00, qclass,
    0x00, 0x00, 0x00, 0x3C,  // TTL 60s
    0x00, rdata.length,
    ...rdata
  ])

  const final = new Uint8Array(header.length + question.length + answer.length)
  final.set(header, 0)
  final.set(question, header.length)
  final.set(answer, header.length + question.length)

  return new Response(final, {
    headers: { 'content-type': contype }
  })
}