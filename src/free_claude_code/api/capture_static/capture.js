(() => {
  "use strict";

  const COLORS = {Bluetooth:"#68a9ff",Network:"#08d49d",WiFi:"#ae8cff",USB:"#eebc65",Serial:"#ef7f78",Raw:"#7d918c"};
  const els = Object.fromEntries([...document.querySelectorAll("[id]")].map((el) => [el.id, el]));
  const state = {packets: [], filtered: [], selected: null, family: "All", file: null, view: "packets"};
  const decoder = new TextDecoder("utf-8", {fatal:false});

  const hex = (value, width=2) => Number(value).toString(16).toUpperCase().padStart(width, "0");
  const mac = (bytes) => [...bytes].map((b) => hex(b)).join(":");
  const ip4 = (bytes) => [...bytes].join(".");
  const formatBytes = (n) => n < 1024 ? `${n} B` : n < 1048576 ? `${(n/1024).toFixed(1)} KB` : `${(n/1048576).toFixed(1)} MB`;
  const escapeHtml = (text) => String(text).replace(/[&<>"']/g, (c) => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"})[c]);
  const read16 = (view, offset, little) => view.getUint16(offset, little);
  const read32 = (view, offset, little) => view.getUint32(offset, little);

  function packetBase(index, time, data, linkType) {
    return {index, time, data, linkType, source:"—", destination:"—", protocol:"RAW", family:"Raw", info:"Unbekannte Nutzdaten", details:[]};
  }

  function decodePacket(packet) {
    const b = packet.data;
    try {
      if (packet.linkType === 1 && b.length >= 14) decodeEthernet(packet);
      else if ([105, 127].includes(packet.linkType)) decodeWiFi(packet);
      else if ([189, 220].includes(packet.linkType)) decodeUsb(packet);
      else if ([187, 201].includes(packet.linkType)) decodeBluetooth(packet, packet.linkType === 201 ? 4 : 0);
      else if (b.length && [1,2,3,4].includes(b[0])) decodeBluetooth(packet, 0);
      else decodeRaw(packet);
    } catch (error) {
      packet.info = `Dekodierung unvollständig: ${error.message}`;
    }
    return packet;
  }

  function decodeEthernet(p) {
    const b=p.data, type=(b[12]<<8)|b[13];
    p.family="Network"; p.source=mac(b.slice(6,12)); p.destination=mac(b.slice(0,6)); p.protocol="ETH";
    p.details.push(["Ethernet II", ""], ["Zieladresse",p.destination],["Quelladresse",p.source],["EtherType",`0x${hex(type,4)}`]);
    let offset=14;
    if (type===0x8100 && b.length>=18) {offset=18; p.details.push(["802.1Q VLAN",String(((b[14]<<8)|b[15])&0xfff)]);}
    const inner=(offset===18)?((b[16]<<8)|b[17]):type;
    if (inner===0x0800 && b.length>=offset+20) decodeIPv4(p,offset);
    else if (inner===0x86dd && b.length>=offset+40) decodeIPv6(p,offset);
    else if (inner===0x0806 && b.length>=offset+28) {p.protocol="ARP";p.info="Address Resolution Protocol";p.source=ip4(b.slice(offset+14,offset+18));p.destination=ip4(b.slice(offset+24,offset+28));}
    else p.info=`Ethernet II, Typ 0x${hex(inner,4)}`;
  }

  function decodeIPv4(p,o) {
    const b=p.data, ihl=(b[o]&15)*4, proto=b[o+9]; p.source=ip4(b.slice(o+12,o+16));p.destination=ip4(b.slice(o+16,o+20));p.protocol="IPv4";
    p.details.push(["Internet Protocol Version 4", ""],["Quelle",p.source],["Ziel",p.destination],["TTL",String(b[o+8])],["Protokoll",String(proto)]);
    decodeTransport(p,o+ihl,proto);
  }
  function decodeIPv6(p,o) {
    const b=p.data, addr=(start)=>Array.from({length:8},(_,i)=>hex((b[start+i*2]<<8)|b[start+i*2+1],4)).join(":");p.source=addr(o+8);p.destination=addr(o+24);p.protocol="IPv6";p.details.push(["Internet Protocol Version 6",""],["Quelle",p.source],["Ziel",p.destination]);decodeTransport(p,o+40,b[o+6]);
  }
  function decodeTransport(p,o,proto) {
    const b=p.data;if (b.length<o+4) return;
    const src=(b[o]<<8)|b[o+1], dst=(b[o+2]<<8)|b[o+3];
    if (proto===6) {p.protocol="TCP";p.info=`${src} → ${dst}  Seq=${b.length>=o+8?read32(new DataView(b.buffer,b.byteOffset,b.byteLength),o+4,false):0}`;p.details.push(["Transmission Control Protocol",""],["Quellport",String(src)],["Zielport",String(dst)]);}
    else if (proto===17) {p.protocol=(src===53||dst===53)?"DNS":"UDP";p.info=`${src} → ${dst}  Len=${Math.max(0,b.length-o-8)}`;p.details.push(["User Datagram Protocol",""],["Quellport",String(src)],["Zielport",String(dst)]);}
    else if (proto===1||proto===58) {p.protocol="ICMP";p.info=`Echo / Control, Typ ${b[o]}`;}
    else p.info=`IP-Protokoll ${proto}`;
  }

  function decodeBluetooth(p, offset) {
    const b=p.data;if (b.length<=offset) return;const type=b[offset];p.family="Bluetooth";p.source="Controller";p.destination="Host";
    const names={1:"HCI CMD",2:"HCI ACL",3:"HCI SCO",4:"HCI EVT"};p.protocol=names[type]||"BT HCI";
    if(type===1&&b.length>=offset+4){const op=b[offset+1]|(b[offset+2]<<8);p.source="Host";p.destination="Controller";p.info=`HCI Command, Opcode 0x${hex(op,4)}, Parameter ${b[offset+3]} B`;p.details.push(["Bluetooth HCI Command",""],["Opcode",`0x${hex(op,4)}`],["Parameterlänge",`${b[offset+3]} Byte`]);}
    else if(type===4&&b.length>=offset+3){const event=b[offset+1];p.info=`HCI Event 0x${hex(event)}, Parameter ${b[offset+2]} B`;p.details.push(["Bluetooth HCI Event",""],["Event-Code",`0x${hex(event)}`],["Parameterlänge",`${b[offset+2]} Byte`]);}
    else if(type===2&&b.length>=offset+5){const handle=(b[offset+1]|(b[offset+2]<<8))&0xfff;const len=b[offset+3]|(b[offset+4]<<8);p.source=`Handle 0x${hex(handle,4)}`;p.destination="Peer";p.info=`ACL Data, Handle 0x${hex(handle,4)}, ${len} B`;p.details.push(["Bluetooth HCI ACL Data",""],["Connection Handle",`0x${hex(handle,4)}`],["Datenlänge",`${len} Byte`]);if(b.length>=offset+9){const cid=b[offset+7]|(b[offset+8]<<8);p.details.push(["L2CAP Channel",`0x${hex(cid,4)}`]);if(cid===4){p.protocol="ATT";p.info+=`, ATT Opcode 0x${hex(b[offset+9]||0)}`;}}}
    else {p.info=`Bluetooth HCI, Pakettyp 0x${hex(type)}`;p.details.push(["Bluetooth HCI",""],["Pakettyp",`0x${hex(type)}`]);}
  }
  function decodeWiFi(p) {const b=p.data;let o=p.linkType===127&&b.length>4?(b[2]|(b[3]<<8)):0;if(b.length<o+24){decodeRaw(p);return;}p.family="WiFi";p.protocol="802.11";p.destination=mac(b.slice(o+4,o+10));p.source=mac(b.slice(o+10,o+16));const type=(b[o]>>2)&3,sub=(b[o]>>4)&15;p.info=`IEEE 802.11 ${["Management","Control","Data","Reserved"][type]}, Subtype ${sub}`;p.details.push(["IEEE 802.11 Wireless LAN",""],["Frame Control",`0x${hex(b[o+1])}${hex(b[o])}`],["Quelle",p.source],["Ziel",p.destination]);}
  function decodeUsb(p) {p.family="USB";p.protocol="USB";p.source="Host";p.destination="Device";p.info=`USB-Transfer, ${p.data.length} Byte`;p.details.push(["USB Capture",""],["Link-Typ",String(p.linkType)],["Erfasste Bytes",String(p.data.length)]);}
  function decodeRaw(p) {const printable=decoder.decode(p.data.slice(0,80)).replace(/[^\x20-\x7E]+/g," ").trim();p.protocol="RAW";p.family="Raw";p.info=printable||`Binärdaten, ${p.data.length} Byte`;p.details.push(["Rohdaten",""],["Länge",`${p.data.length} Byte`],["Vorschau",printable||"Keine druckbaren Zeichen"]);}

  function parsePcap(bytes, start=0) {
    const v=new DataView(bytes.buffer,bytes.byteOffset,bytes.byteLength);if(bytes.length-start<24)throw new Error("PCAP-Header ist unvollständig.");
    const magic=v.getUint32(start,false);const little=[0xd4c3b2a1,0x4d3cb2a1].includes(magic);const nano=[0xa1b23c4d,0x4d3cb2a1].includes(magic);const linkType=read32(v,start+20,little);let o=start+24,index=1;const packets=[];let first=null;
    while(o+16<=bytes.length){const sec=read32(v,o,little),frac=read32(v,o+4,little),cap=read32(v,o+8,little);if(cap>bytes.length-o-16||cap>64*1024*1024)break;const absolute=sec+frac/(nano?1e9:1e6);if(first===null)first=absolute;packets.push(decodePacket(packetBase(index++,absolute-first,bytes.slice(o+16,o+16+cap),linkType)));o+=16+cap;}
    return {packets,format:start?"CFA · eingebettetes PCAP":"PCAP",linkType};
  }

  function parsePcapng(bytes, start=0) {
    const v=new DataView(bytes.buffer,bytes.byteOffset,bytes.byteLength);let o=start,little=true,index=1,first=null;const interfaces=[],packets=[];
    while(o+12<=bytes.length){let type=v.getUint32(o,little);if(o===start){type=v.getUint32(o,false);if(type!==0x0a0d0d0a)throw new Error("Ungültiger PCAPNG-Header.");const bom=v.getUint32(o+8,false);little=bom===0x4d3c2b1a;}
      const len=v.getUint32(o+4,little);if(len<12||o+len>bytes.length)break;
      if(type===1&&len>=20) interfaces.push({linkType:v.getUint16(o+8,little),resolution:1e6});
      if(type===6&&len>=32){const iface=read32(v,o+8,little),hi=read32(v,o+12,little),lo=read32(v,o+16,little),cap=read32(v,o+20,little);if(o+28+cap<=bytes.length){const absolute=(hi*4294967296+lo)/(interfaces[iface]?.resolution||1e6);if(first===null)first=absolute;packets.push(decodePacket(packetBase(index++,absolute-first,bytes.slice(o+28,o+28+cap),interfaces[iface]?.linkType||1)));}}
      o+=len;
    }
    return {packets,format:start?"CFA · eingebettetes PCAPNG":"PCAPNG",linkType:interfaces.map(i=>i.linkType).join(", ")};
  }

  function findEmbeddedCapture(bytes) {for(let i=0;i<=Math.min(bytes.length-4,8*1024*1024);i++){const a=bytes[i],b=bytes[i+1],c=bytes[i+2],d=bytes[i+3];if((a===0x0a&&b===0x0d&&c===0x0d&&d===0x0a)||(a===0xd4&&b===0xc3&&c===0xb2&&d===0xa1)||(a===0xa1&&b===0xb2&&c===0xc3&&d===0xd4)||(a===0x4d&&b===0x3c&&c===0xb2&&d===0xa1))return i;}return -1;}
  function parseRawCfa(bytes) {const packets=[];const chunk=256;for(let o=0,index=1;o<bytes.length;o+=chunk,index++){const data=bytes.slice(o,Math.min(bytes.length,o+chunk));const p=decodePacket(packetBase(index,o/1000000,data,0));p.info=`CFA-Rohblock @ 0x${hex(o,8)} · ${p.info}`;packets.push(p);}return {packets,format:"CFA · Rohdatenmodus",linkType:"unbekannt",warning:"Proprietärer CFA-Container: Rohdaten werden in Blöcken angezeigt. Für vollständige Protokolldekodierung aus dem Herstellerwerkzeug als PCAP/PCAPNG exportieren."};}
  function parseCapture(bytes,name) {if(bytes.length<4)throw new Error("Die Datei ist leer oder zu klein.");const m=new DataView(bytes.buffer,bytes.byteOffset,bytes.byteLength).getUint32(0,false);if(m===0x0a0d0d0a)return parsePcapng(bytes);if([0xa1b2c3d4,0xd4c3b2a1,0xa1b23c4d,0x4d3cb2a1].includes(m))return parsePcap(bytes);if(name.toLowerCase().endsWith(".cfa")){const offset=findEmbeddedCapture(bytes);if(offset>=0)return bytes[offset]===0x0a?parsePcapng(bytes,offset):parsePcap(bytes,offset);return parseRawCfa(bytes);}throw new Error("Dieses Format wird nicht erkannt. Unterstützt werden CFA, PCAP, PCAPNG und CAP.");}

  async function openFile(file) {try{const bytes=new Uint8Array(await file.arrayBuffer());const parsed=parseCapture(bytes,file.name);state.packets=parsed.packets;state.file={name:file.name,size:file.size,format:parsed.format,linkType:parsed.linkType};state.family="All";state.selected=null;showAnalyzer();renderAll();if(parsed.warning)toast(parsed.warning,6500);else toast(`${parsed.packets.length.toLocaleString("de-DE")} Pakete geladen`);}catch(error){toast(error.message||"Datei konnte nicht geöffnet werden.",5000);}}

  function makeDemo() {const packets=[];let time=0;const add=(family,protocol,src,dst,info,data)=>{const p=packetBase(packets.length+1,time,new Uint8Array(data),0);Object.assign(p,{family,protocol,source:src,destination:dst,info,details:[[`${protocol} Demo-Frame`,""],["Quelle",src],["Ziel",dst],["Beschreibung",info]]});packets.push(p);time+=.0018+Math.random()*.025;};
    for(let i=0;i<86;i++){if(i%5===0)add("Bluetooth",i%10===0?"ATT":"HCI ACL",`Handle 0x${hex(64+i,4)}`,"Pixel Buds",i%10===0?"ATT Read Response, Attribute 0x0025":"L2CAP Data, CID 0x0004",[2,1,i,8,0,4,0,4,0,0x0b,0x32,0x41]);else if(i%7===0)add("WiFi","802.11","A4:71:74:8C:2D:10","FF:FF:FF:FF:FF:FF","Beacon frame, SSID: Lab-Network",[128,0,0,0,255,255,255,255,255,255]);else if(i%11===0)add("USB","USB","Host",`Device ${i%4+1}`,"URB_BULK in, Status: Success",[0,1,2,3,i]);else add("Network",i%3===0?"DNS":"TCP",`192.168.1.${20+i%6}`,i%3===0?"1.1.1.1":"142.250.185.78",i%3===0?"Standard query A api.example.dev":`443 → ${51000+i} [ACK] Seq=${i*1440}`,[69,0,0,i,8,0,69,0,0,2]);}
    state.packets=packets;state.file={name:"bluetooth-lab-demo.cfa",size:182440,format:"CFA Demo",linkType:"HCI · Ethernet · 802.11 · USB"};state.family="All";state.selected=null;showAnalyzer();renderAll();toast("Demo-Capture geladen");}

  function protocolFamilies(){const counts={};for(const p of state.packets)counts[p.family]=(counts[p.family]||0)+1;return counts;}
  function renderProtocolFilters(){const counts=protocolFamilies();const order=["All","Bluetooth","Network","WiFi","USB","Serial","Raw"];els.protocolFilters.innerHTML=order.filter(f=>f==="All"||counts[f]).map(f=>`<button class="protocol-button ${state.family===f?"active":""}" data-family="${f}" style="--protocol-color:${f==="All"?"#08d49d":COLORS[f]}"><i></i><span>${f==="All"?"Alle Verbindungen":f}</span><b>${f==="All"?state.packets.length:counts[f]}</b></button>`).join("");}

  function compileFilter(text) {
    const query = text.trim();
    if (!query) return () => true;
    const fields = /^(?:(protocol|family|source|destination|src|dst|info|length|len|number|no|time)\s*(==|=|!=|>=|<=|>|<|contains)\s*)?(.+)$/i;
    const groups = query.split(/\s*\|\|\s*/).map((part) =>
      part.split(/\s*&&\s*/).map((clause) => {
        const match = clause.trim().match(fields);
        if (!match) throw new Error(`Ungültiger Ausdruck: ${clause}`);
        let [, field, operator, value] = match;
        if (!field) {
          return (packet) => [packet.protocol, packet.family, packet.source, packet.destination, packet.info]
            .some((candidate) => String(candidate).toLowerCase().includes(value.toLowerCase()));
        }
        field = field.toLowerCase();
        operator = operator.toLowerCase();
        value = value.replace(/^['"]|['"]$/g, "");
        const key = {src:"source", dst:"destination", len:"length", no:"number"}[field] || field;
        return (packet) => {
          const actual = key === "length" ? packet.data.length : key === "number" ? packet.index : packet[key];
          if ([">", "<", ">=", "<="].includes(operator)) {
            const left = Number(actual), right = Number(value);
            if (operator === ">") return left > right;
            if (operator === "<") return left < right;
            if (operator === ">=") return left >= right;
            return left <= right;
          }
          const left = String(actual).toLowerCase(), right = value.toLowerCase();
          if (operator === "!=") return left !== right;
          if (operator === "contains") return left.includes(right);
          return left === right;
        };
      })
    );
    return (packet) => groups.some((group) => group.every((test) => test(packet)));
  }

  function applyFilters(){try{const test=compileFilter(els.displayFilter.value);state.filtered=state.packets.filter(p=>(state.family==="All"||p.family===state.family)&&test(p));els.filterError.hidden=true;}catch(error){state.filtered=[];els.filterError.textContent=error.message;els.filterError.hidden=false;}renderPackets();renderSummary();}
  function renderPackets(){els.packetRows.innerHTML=state.filtered.slice(0,5000).map(p=>`<tr data-index="${p.index}" class="${state.selected?.index===p.index?"selected":""}" style="--protocol-color:${COLORS[p.family]||COLORS.Raw}"><td>${p.index}</td><td>${p.time.toFixed(6)}</td><td title="${escapeHtml(p.source)}">${escapeHtml(p.source)}</td><td title="${escapeHtml(p.destination)}">${escapeHtml(p.destination)}</td><td><span class="protocol-pill">${escapeHtml(p.protocol)}</span></td><td>${p.data.length}</td><td title="${escapeHtml(p.info)}">${escapeHtml(p.info)}</td></tr>`).join("");els.emptyState.hidden=state.filtered.length>0;if(state.filtered.length>5000)toast(`Zur Performance werden die ersten 5.000 von ${state.filtered.length} Paketen angezeigt.`);}
  function renderInspector(p){state.selected=p;els.selectedPacketTitle.textContent=p?`Paket ${p.index} · ${p.protocol} · ${p.data.length} Byte`:"Kein Paket gewählt";if(!p){els.detailsTab.innerHTML='<p class="placeholder">Wähle ein Paket aus der Liste.</p>';els.bytesTab.innerHTML="";return;}const sections=[];for(const [key,value] of p.details){sections.push(value===""?`<div class="tree-section" style="--protocol-color:${COLORS[p.family]||COLORS.Raw}">${escapeHtml(key)}</div>`:`<div class="tree-row"><strong>${escapeHtml(key)}</strong><span>${escapeHtml(value)}</span></div>`);}els.detailsTab.innerHTML=sections.join("");const lines=[];for(let o=0;o<p.data.length;o+=16){const chunk=p.data.slice(o,o+16);lines.push(`<div class="hex-line"><span class="offset">${hex(o,8)}</span><span class="bytes">${[...chunk].map(b=>hex(b)).join(" ").padEnd(47," ")}</span><span class="ascii">${[...chunk].map(b=>b>=32&&b<=126?String.fromCharCode(b):".").join("")}</span></div>`);}els.bytesTab.innerHTML=lines.join("")||'<p class="placeholder">Keine Bytes vorhanden.</p>';renderPackets();}
  function conversations(){const map=new Map();for(const p of state.filtered){const ends=[p.source,p.destination].sort();const key=`${p.protocol}|${ends[0]}|${ends[1]}`;const row=map.get(key)||{protocol:p.protocol,a:ends[0],b:ends[1],packets:0,bytes:0,family:p.family};row.packets++;row.bytes+=p.data.length;map.set(key,row);}return [...map.values()].sort((a,b)=>b.packets-a.packets);}
  function renderSummary(){els.packetCount.textContent=state.filtered.length;const conv=conversations();els.conversationCount.textContent=conv.length;const total=state.filtered.reduce((n,p)=>n+p.data.length,0);els.conversationRows.innerHTML=conv.map(c=>`<tr><td><span class="protocol-pill" style="--protocol-color:${COLORS[c.family]}">${escapeHtml(c.protocol)}</span></td><td>${escapeHtml(c.a)}</td><td>${escapeHtml(c.b)}</td><td>${c.packets}</td><td>${formatBytes(c.bytes)}</td><td>${state.filtered.length?((c.packets/state.filtered.length)*100).toFixed(1):0}%</td></tr>`).join("");els.statPackets.textContent=state.filtered.length.toLocaleString("de-DE");els.statBytes.textContent=formatBytes(total);const prot=[...new Set(state.filtered.map(p=>p.protocol))];els.statProtocols.textContent=prot.length;els.statAverage.textContent=formatBytes(state.filtered.length?Math.round(total/state.filtered.length):0);const duration=state.filtered.length?Math.max(...state.filtered.map(p=>p.time))-Math.min(...state.filtered.map(p=>p.time)):0;els.captureDuration.textContent=`Dauer ${duration.toFixed(3)} Sekunden`;const counts=protocolFamiliesFor(state.filtered);const max=Math.max(1,...Object.values(counts));els.protocolChart.innerHTML=Object.entries(counts).sort((a,b)=>b[1]-a[1]).map(([family,count])=>`<div class="chart-column" style="--protocol-color:${COLORS[family]||COLORS.Raw}"><i style="height:${Math.max(3,(count/max)*170)}px"></i><b>${family}<br>${count}</b></div>`).join("");}
  function protocolFamiliesFor(packets){const c={};for(const p of packets)c[p.family]=(c[p.family]||0)+1;return c;}
  function renderAll(){renderProtocolFilters();applyFilters();els.fileName.textContent=state.file.name;els.fileMeta.textContent=`${formatBytes(state.file.size)} · ${state.file.format}`;els.fileSummary.hidden=false;}
  function showAnalyzer(){els.welcomeView.hidden=true;els.analyzerView.hidden=false;}
  function closeCapture(){state.packets=[];state.filtered=[];state.selected=null;els.analyzerView.hidden=true;els.welcomeView.hidden=false;els.fileSummary.hidden=true;els.fileInput.value="";els.displayFilter.value="";}
  function setView(name){state.view=name;document.querySelectorAll(".side-link").forEach(b=>b.classList.toggle("active",b.dataset.view===name));["packets","conversations","statistics"].forEach(v=>els[`${v}View`].hidden=v!==name);}
  function toast(message,duration=2600){els.toast.textContent=message;els.toast.classList.add("show");clearTimeout(toast.timer);toast.timer=setTimeout(()=>els.toast.classList.remove("show"),duration);}
  function exportData(format){const base=(state.file?.name||"capture").replace(/\.[^.]+$/,"");let content,type,ext;if(format==="json"){content=JSON.stringify(state.filtered.map(p=>({number:p.index,time:p.time,source:p.source,destination:p.destination,protocol:p.protocol,family:p.family,length:p.data.length,info:p.info,hex:[...p.data].map(b=>hex(b)).join("")})),null,2);type="application/json";ext="json";}else{const quote=v=>`"${String(v).replaceAll('"','""')}"`;content="number,time,source,destination,protocol,family,length,info\n"+state.filtered.map(p=>[p.index,p.time,p.source,p.destination,p.protocol,p.family,p.data.length,p.info].map(quote).join(",")).join("\n");type="text/csv";ext="csv";}const a=document.createElement("a");a.href=URL.createObjectURL(new Blob([content],{type}));a.download=`${base}-filtered.${ext}`;a.click();setTimeout(()=>URL.revokeObjectURL(a.href),1000);els.exportMenu.hidden=true;toast(`${state.filtered.length} Pakete als ${format.toUpperCase()} exportiert`);}

  [els.openButton,els.heroOpenButton].forEach(b=>b.addEventListener("click",()=>els.fileInput.click()));els.dropZone.addEventListener("click",()=>els.fileInput.click());els.fileInput.addEventListener("change",()=>els.fileInput.files[0]&&openFile(els.fileInput.files[0]));els.demoButton.addEventListener("click",makeDemo);els.closeButton.addEventListener("click",closeCapture);
  ["dragenter","dragover"].forEach(e=>els.dropZone.addEventListener(e,event=>{event.preventDefault();els.dropZone.classList.add("drag");}));["dragleave","drop"].forEach(e=>els.dropZone.addEventListener(e,event=>{event.preventDefault();els.dropZone.classList.remove("drag");}));els.dropZone.addEventListener("drop",e=>e.dataTransfer.files[0]&&openFile(e.dataTransfer.files[0]));
  els.protocolFilters.addEventListener("click",e=>{const b=e.target.closest("[data-family]");if(!b)return;state.family=b.dataset.family;renderProtocolFilters();applyFilters();});els.displayFilter.addEventListener("input",applyFilters);els.clearFilter.addEventListener("click",()=>{els.displayFilter.value="";applyFilters();els.displayFilter.focus();});els.packetRows.addEventListener("click",e=>{const row=e.target.closest("tr[data-index]");if(row)renderInspector(state.packets.find(p=>p.index===Number(row.dataset.index)));});document.querySelectorAll(".side-link").forEach(b=>b.addEventListener("click",()=>setView(b.dataset.view)));document.querySelectorAll(".tabs button").forEach(b=>b.addEventListener("click",()=>{document.querySelectorAll(".tabs button").forEach(x=>x.classList.toggle("active",x===b));els.detailsTab.hidden=b.dataset.tab!=="details";els.bytesTab.hidden=b.dataset.tab!=="bytes";}));els.exportButton.addEventListener("click",()=>els.exportMenu.hidden=!els.exportMenu.hidden);els.exportMenu.addEventListener("click",e=>e.target.dataset.format&&exportData(e.target.dataset.format));document.addEventListener("click",e=>{if(!e.target.closest(".export-button")&&!e.target.closest(".export-menu"))els.exportMenu.hidden=true;});
})();
