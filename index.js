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
            } else {
                console.log("LocalDNS miss:", qname, type)
            }
        } else {
            console.log("Failed to parse DNS question")
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
function buildWireFormatResponse(qname, type, ipValue, reqBuf) {
    const encoder = new TextEncoder();
  
    // Convert name to wire format (label1.length + label1 + ... + 0)
    const labels = qname.slice(0, -1).split('.');
    const nameBuf = [];
    for (const label of labels) {
      const enc = encoder.encode(label);
      nameBuf.push(enc.length, ...enc);
    }
    nameBuf.push(0); // terminator
  
    const nameBytes = Uint8Array.from(nameBuf);
    const qtype = type === 'A' ? 1 : 28;
    const qclass = 1;
  
    // Parse header from request
    const id = reqBuf.slice(0, 2); // Copy request ID
    const flags = new Uint8Array([0x81, 0x80]); // Standard response, recursion available
    const qdcount = new Uint8Array([0x00, 0x01]);
    const ancount = new Uint8Array([0x00, 0x01]);
    const nscount = new Uint8Array([0x00, 0x00]);
    const arcount = new Uint8Array([0x00, 0x00]);
  
    const header = concatUint8Arrays(id, flags, qdcount, ancount, nscount, arcount);
  
    // Build question section (name + type + class)
    const question = concatUint8Arrays(
      nameBytes,
      new Uint8Array([0x00, qtype]), // QTYPE
      new Uint8Array([0x00, qclass]) // QCLASS
    );
  
    // Prepare IP address data
    const ipStr = Array.isArray(ipValue) ? ipValue[0] : ipValue;
    let rdata;
    if (type === 'A') {
      rdata = Uint8Array.from(ipStr.split('.').map(n => parseInt(n)));
    } else if (type === 'AAAA') {
      const segments = ipStr.split(':').map(s => parseInt(s || '0', 16));
      rdata = new Uint8Array(16);
      for (let i = 0; i < segments.length; i++) {
        rdata[i * 2] = (segments[i] >> 8) & 0xff;
        rdata[i * 2 + 1] = segments[i] & 0xff;
      }
    } else {
      throw new Error("Unsupported record type");
    }
  
    // Build answer section (name + type + class + ttl + rdlength + rdata)
    const answer = concatUint8Arrays(
      nameBytes,
      new Uint8Array([0x00, qtype]), // TYPE
      new Uint8Array([0x00, qclass]), // CLASS
      new Uint8Array([0x00, 0x00, 0x00, 0x3C]), // TTL: 60s
      new Uint8Array([0x00, rdata.length]), // RDLENGTH
      rdata
    );
  
    const packet = concatUint8Arrays(header, question, answer);
    return new Response(packet, {
      headers: { 'content-type': 'application/dns-message' }
    });
  }
  
  // Helper to merge Uint8Arrays
  function concatUint8Arrays(...arrays) {
    const totalLength = arrays.reduce((sum, arr) => sum + arr.length, 0);
    const result = new Uint8Array(totalLength);
    let offset = 0;
    for (const arr of arrays) {
      result.set(arr, offset);
      offset += arr.length;
    }
    return result;
  }