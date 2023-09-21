const urlReg = new RegExp(`otpauth:\\/\\/.*?\\/.*?$`, "gm")
const urlMainReg = new RegExp(`\\/\\/(.*?)\\/(.*?)((:(.*))|$)`)
const urlParamsReg = new RegExp(`([^&]+?)=([^&]+)`, "g")
const totpconfigReg = new RegExp(`(.+?):(.+)`, "g")
const ALGOMAP = {
    to:["SHA1", "SHA256", "SHA512", "STEAM"],
    from:{
        "SHA1":0,
        "SHA256":1,
        "SHA512":2,
        "STEAM":3
    }
}

// defaults
var DEFAULTS = {
    Filetype: "Flipper TOTP plugin config file",
    Version:undefined,
    CryptoVersion:undefined,
    CryptoKeySlot:undefined,
    Salt:undefined,
    Crypto:undefined,
    Timezone:0,
    PinIsSet:false,
    NotificationMethod:3,
    AutomationMethod:1,
    Font:0,
    AutomationKbLayout:0
}
var HEADER = {
    Filetype: "Flipper TOTP plugin config file",
    Version:undefined,
    CryptoVersion:undefined,
    CryptoKeySlot:undefined,
    Salt:undefined,
    Crypto:undefined,
    Timezone:0,
    PinIsSet:false,
    NotificationMethod:3,
    AutomationMethod:1,
    Font:0,
    AutomationKbLayout:0
}

var FILE_STATE = {
    exports:{},
    totp:{}
}

function shorten(string, start, end) {
    if(start+end+3>=string.length){
        return string
    }
    return string.slice(0,start)+"..."+string.slice(-end)
}

async function parseFileList(list) {
    FILE_STATE.exports = {}
    progress = document.getElementById(`drag${zone}2`)
    if(list.length==0){
        // should never happen in practice, but who knows
        document.getElementById(`drag${zone}0`).style.display = 'flex'
        document.getElementById(`drag${zone}1`).style.display = 'none'
        progress.style.display = 'none'
        return
    }
    AUTH_FILES = list
    console.log(list)
    document.getElementById(`drag${zone}0`).style.display = 'none'
    document.getElementById(`drag${zone}1`).style.display = 'none'
    progress = document.getElementById(`drag${zone}2`)
    
    for (const item of list) {
        readFileAsync(item)
    }

    progress.innerHTML = list.length>1?
    `<div class="pad"><span id="loadtext0">LOADED ${list.length} FILES ...</span></div>`:
    `<div class="pad"><span id="loadtext0">LOADED ${shorten(list[0].name, 12, 6)} ...</span></div>`
    progress.style.display = 'flex'
}

function log(msg, type, context) {
    console.log(msg)
}

function loaderError(message, zone) {
    document.getElementById(`drag${zone}0`).style.display = 'none'
    document.getElementById(`drag${zone}1`).style.display = 'none'
    progress = document.getElementById(`drag${zone}2`)
    progress.innerHTML = `<div class="pad"><span id="loadtext0">ERROR: ${message}</span></div>`
    progress.style.display = 'flex'
}

async function readFileAsync(file, context) {
    const reader = new FileReader();
    reader.addEventListener('load', (event) => {
        extractDataRaw(event?.target?.result).then(
            r=>{
                if(r.error){
                    log(`FILE: ${file.name}: `+r.error, "error", file.name)
                    loaderError(r.error, 1)
                    return
                }
                flipperizeEntries(r).then(x=>console.log(x.data))
            }
            )
    });
    reader.readAsText(file);
}

function getFileType(content) {
    try {
        JSONcontents = JSON.parse(content)
        return "json"
    } catch (error) {
        // ignore
    }

    if(content.toLowerCase().trim().startsWith("<html><head><title>")){
        return "html"
    }

    if(content.toLowerCase().trim().startsWith("otpauth://")){
        return "url"
    }

    return "invalid"
}

async function extractDataRaw(content) {
    ftype = getFileType(content)
    
    switch (ftype) {
        case "json":
            if(JSONcontents?.db?.version === undefined){
                return {
                    isEncrypted: true,
                    data: JSONcontents
                }
            }
            return {
                isEncrypted: false,
                data: JSONcontents?.db?.entries || []
            }
        case "url":
            urls = [...content.matchAll(urlReg)].map(e=>e[0])
            entries = []
            for (const u of urls) {
                let uobject
                try {
                    uobject = new URL(u)
                } catch (error) {
                    entries.push({
                        error:"Invalid URL",
                        entry_data:u
                    })
                    continue
                }

                // 1-type, 2-issuer, 5-name || 1-type, 2-name
                groups = decodeURIComponent(uobject?.pathname).match(urlMainReg) 
                if(groups?.length!==6){
                    entries.push({
                        error:"Could not decode type/issuer/name from URL",
                        entry_data:u
                    })
                    continue 
                }
                params = [...(uobject?.search || "?").slice(1).matchAll(urlParamsReg)].reduce((obj, item) => {
                    return {
                        ...obj,
                        [item[1]]:decodeURIComponent(item[2]),
                    }
                }, {})
                
                // Sometimes Issuer in URL parameter does not match real issuer due to faulty exports. Taking the longest one.
                if(params?.issuer !== undefined && groups[5]!==""){
                    issuer_fix = (params?.issuer?.length<groups[2].length)?groups[2]:params?.issuer
                } else {
                    issuer_fix = params?.issuer||groups[2]
                }
                entries.push({
                    type:groups[1].toLowerCase(),
                    name:(groups[5]!=="" && groups[5]!==undefined)?groups[5]:groups[2],
                    issuer:(groups[5]!=="" && groups[5]!==undefined)?issuer_fix:"",
                    info:{
                        secret: params?.secret,
                        algo:params?.algo || "SHA1",
                        digits:Number(params?.digits) || 6,
                        period:Number(params?.period) || 30
                    }
                })

            }
            return {isEncrypted: false, data:entries}
        case "html":
            return {
                error: "Reading HTML file is not yet implemented"
            }
    
        default:
            return {
                error: "Could not recognize file format"
            }
    }
}

async function flipperizeEntries(data) {
    if(data.isEncrypted){
        return {
            error:"Export is encrypted. Decryption is not yet implemented"
        }
    }
    acc = ""
    for (const entry of data.data) {
        if (entry.error) {
            continue
        }
        acc += `
TokenName: ${entry.issuer!==""?entry.issuer+": "+entry.name:entry.name}
TokenSecret: ${entry.info.secret}
TokenAlgo: ${entry.type.toLowerCase()!=="steam"?ALGOMAP.from[entry.info.algo.toUpperCase()]:ALGOMAP.from["STEAM"]}
TokenDigits: ${entry.info.digits}
TokenDuration: ${entry.info.period}
TokenAutomationFeatures: ${entry.flipper_automation!==undefined?entry.flipper_automation:0}`
    }
    return {data:acc}
}

async function readTotpConfigHeader(file) {
    const reader = new FileReader();
    reader.addEventListener('load', (event) => {
        content = event?.target?.result
        expected_keys = Object.keys(HEADER)
        for (const l of content.split(new RegExp(`\n`))) {
            groups = l.match(totpconfigReg)
            if(groups===null || groups?.length<2){
                continue
            }
            k = groups[1].trim()
            v = groups[2].trim()
            if(!expected_keys.includes(k)){
                continue
            }
            HEADER[k] = v
        }
        console.log(HEADER)
    });
    reader.readAsText(file);
}

async function readTotpFile(event) {
    event.preventDefault()
    if (event.dataTransfer.items) {

        t = [];
        [...event.dataTransfer.items].forEach((item, i) => {
          if (item.kind === "file") {
            t.push(item.getAsFile()) 
          }
        });
        if(t.length>0){
            readTotpConfigHeader(t[0])
        } else {
            log("No file was selected for totp.conf")
            zone = 0
            document.getElementById(`drag${zone}0`).style.display = 'flex'
            document.getElementById(`drag${zone}1`).style.display = 'none'
            document.getElementById(`drag${zone}2`).style.display = 'none'
        }
      } else {
        s = [...event.dataTransfer.files]
        if(s.length>0){
            readTotpConfigHeader(s[0])
        } else {
            log("No file was selected for totp.conf")
            zone = 0
            document.getElementById(`drag${zone}0`).style.display = 'flex'
            document.getElementById(`drag${zone}1`).style.display = 'none'
            document.getElementById(`drag${zone}2`).style.display = 'none'
        }
      }

    
}

async function toggleFileOver(event, state, context) {
    event.preventDefault()

    // find which block to toggle
    zone = event.target.parentElement.id.replaceAll("z","")
    if(isNaN(Number(zone))){
        // rare case where drop hits the button
        zone = context
    }
    console.log(zone)
    if(state){
        document.getElementById(`drag${zone}0`).style.display = 'none'
        document.getElementById(`drag${zone}1`).style.display = 'flex'
        document.getElementById(`drag${zone}2`).style.display = 'none'
        // console.log(document.getElementById(`drag${zone}0`).style.display = 'none')
    } else {
        document.getElementById(`drag${zone}0`).style.display = 'flex'
        document.getElementById(`drag${zone}1`).style.display = 'none'
        document.getElementById(`drag${zone}2`).style.display = 'none'
    }
}

async function fileSelector(variant) {
    try {
        switch (variant) {
            case 'totp':
                x = await showOpenFilePicker({
                    multiple:false
                })
                l = x.map(e=>e.getFile())
                if(l?.length>0){
                    readTotpConfigHeader((await Promise.all(l))[0])
                } else {
                    log("No file was selected for totp.conf")
                }
                break;
            case 'exports':
                x = await showOpenFilePicker({
                    multiple:true
                })
                l = x.map(e=>e.getFile())
                if(l?.length>0){
                    parseFileList(await Promise.all(l))
                } else {
                    log("No files were selected for authenticator exports")
                }
                break;
        
            default:
                break;
        }
    } catch (error) {
        // filepick failed
    }
    
}

async function allowDrop(event) {
    event.preventDefault()
}

async function dropfiles(event) {
    
    event.preventDefault()

    if (event.dataTransfer.items) {
        // Use DataTransferItemList interface to access the file(s)
        t = [];
        [...event.dataTransfer.items].forEach((item, i) => {
          // If dropped items aren't files, reject them
          if (item.kind === "file") {
            t.push(item.getAsFile()) 
          }
        });
        parseFileList(t)
      } else {
        // Use DataTransfer interface to access the file(s)
        parseFileList([...event.dataTransfer.files])
      }
}