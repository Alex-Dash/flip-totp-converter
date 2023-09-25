const urlReg = new RegExp(`otpauth:\\/\\/.*?\\/.*?$`, "gm")
const urlMainReg = new RegExp(`\\/\\/(.*?)\\/(.*?)((:(.*))|$)`)
const urlParamsReg = new RegExp(`([^&]+?)=([^&]+)`, "g")
const totpconfigReg = new RegExp(`(.+?):(.+)`, "g")
const sleep = ms => new Promise(r => setTimeout(r, ms));

const ALGOMAP = {
    to:["SHA1", "SHA256", "SHA512", "STEAM"],
    from:{
        "SHA1":0,
        "SHA256":1,
        "SHA512":2,
        "STEAM":3
    }
}

const TYPEINFO = {
    totpconfig:{
        header:{
            Filetype:{
                type: "string",
                protected: true,
                default: "Flipper TOTP plugin config file"
            },
            Version:{
                type: "int",
                protected: true
            },
            CryptoVersion:{
                type: "int",
                protected: true
            },
            CryptoKeySlot:{
                type: "int",
                protected: true
            },
            Salt:{
                type: "bytearray",
                protected: true
            },
            Crypto:{
                type: "bytearray",
                protected: true
            },
            Timezone:{
                type: "float",
                protected: false,
                default: 0.0
            },
            PinIsSet:{
                type: "bool",
                protected: true,
                set: [
                    {label:"Yes", value: true},
                    {label:"No", value: false},
                ],
                default:0
            },
            NotificationMethod:{
                type: "int",
                protected: false,
                set: [
                    {label:"Do not notify", value: 0},
                    {label:"Sound only", value: 1},
                    {label:"Vibro only", value: 2},
                    {label:"Sound and vibro", value: 3},
                ],
                default:3
            },
            AutomationMethod:{
                type: "int",
                protected: false,
                set: [
                    {label:"None", value: 0},
                    {label:"USB", value: 1},
                    {label:"Bluetooth", value: 2},
                    {label:"USB and Bluetooth", value: 3},
                ],
                default:1
            },
            Font:{
                type: "int",
                protected: false,
                set: [
                    {label:"Mode Nine", value: 0},
                    {label:"712 Serif", value: 1},
                    {label:"Bedstead", value: 2},
                    {label:"DP Comic", value: 3},
                    {label:"Fun Climbing", value: 4},
                    {label:"Graph 35pix", value: 5},
                    {label:"Karma Future", value: 6},
                    {label:"Pixel Flag", value: 7},
                    {label:"RedHat Mono", value: 8},
                    {label:"Zector", value: 9},
                ],
                default:0
            },
            AutomationKbLayout:{
                type: "float",
                protected: false,
                set: [
                    {label:"QWERTY", value: 0},
                    {label:"AZERTY", value: 1},
                    {label:"QWERTZ", value: 2}
                ],
                default:0

            }
        },
        entry:{
            TokenName: {
                type: "string",
                protected: false,
                default: "Unnamed token"
            },
            TokenSecret: {
                type: "string",
                protected: false,
                default:"<Paste your secret here>"
            },
            TokenAlgo: {
                type: "int",
                protected: false,
                set: [
                    {label:"SHA1", value: 0},
                    {label:"SHA256", value: 1},
                    {label:"SHA512", value: 2},
                    {label:"STEAM", value: 3},
                ],
                default:0
            },
            TokenDigits: {
                type: "int",
                protected: false,
                set: [
                    {label:"5", value: 5},
                    {label:"6", value: 6},
                    {label:"8", value: 8},
                ],
                default:1
            },
            TokenDuration: {
                type: "int",
                protected: false,
                default:30
            },
            TokenAutomationFeatures: {
                type: "int",
                protected: false,
                set: [
                    {label:"None", value: 0},
                    {label:"Press Enter", value: 1},
                    {label:"Press Tab", value: 2},
                    {label:"Type Slower", value: 4},
                    {label:"Type Slower and press Enter", value: 5},
                    {label:"Type Slower and press Tab", value: 6},
                ],
                default:0
            }
        }
    }
}

const LOCALIZATION = {
    totpconf:{
        "Filetype": "File type",
        "Version": "Version",
        "CryptoVersion": "Crypto Version",
        "CryptoKeySlot": "Crypto Key Slot",
        "BaseIV":"Base IV",
        "Salt": "Salt",
        "Crypto": "Crypto",
        "Timezone": "Timezone Offset (hrs)",
        "PinIsSet": "Pin Set",
        "NotificationMethod": "Notification Method",
        "AutomationMethod": "Automation Method",
        "Font": "Font",
        "AutomationKbLayout": "Automation Keyboard Layout",
        "TokenName": "Token Name",
        "TokenSecret": "Secret",
        "TokenAlgo": "Algorithm",
        "TokenDigits": "Digits",
        "TokenDuration": "Duration",
        "TokenAutomationFeatures": "Automation Features"
    }
}

var PARAMS_LOCKED = true

// defaults
var DEFAULTS = {
    Filetype: "Flipper TOTP plugin config file",
    Version:null,
    CryptoVersion:null,
    CryptoKeySlot:null,
    Salt:null,
    Crypto:null,
    Timezone:0,
    PinIsSet:false,
    NotificationMethod:3,
    AutomationMethod:1,
    Font:0,
    AutomationKbLayout:0
}

// preloaded header
var HEADER = JSON.parse(JSON.stringify(DEFAULTS))

var TOKEN_ENTRIES = []
var ALL_TOKEN_ENTRIES = []

var FILE_STATE = {
    exports:[],
    totp:[]
}

var VALID_FOR_EXPORT = []
var invalid_entries = []

var force_user_inputted_tz = false

function shorten(string, start, end) {
    if(start+end+3>=string.length){
        return string
    }
    return string.slice(0,start)+"..."+string.slice(-end)
}

async function parseFileList(list) {
    recordFileState("exports")
    TOKEN_ENTRIES = []
    progress = document.getElementById(`drag${zone}2`)
    if(list.length==0){
        // should never happen in practice, but who knows
        document.getElementById(`drag${zone}0`).style.display = 'flex'
        document.getElementById(`drag${zone}1`).style.display = 'none'
        progress.style.display = 'none'
        return
    }
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
    document.getElementById("log-target").innerHTML = `<div class="log-msg"><p>[${type===undefined?"INFO":type.toUpperCase()}] ${msg}</p></div>
${document.getElementById("log-target").innerHTML}`
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
        extractDataRaw(event?.target?.result, file).then(
            r=>{
                if(r.error){
                    log(`FILE: ${file.name}: `+r.error, "error", file.name)
                    loaderError(r.error, 1)
                    return
                }
                flipperizeEntries(r).then(x=>{
                    TOKEN_ENTRIES.push(x?.data || [])
                    console.log(x)
                })
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

async function recordFileState(type, file_ref) {
    p = await new Promise((rs,rj)=>{
        if(type===undefined){
            // clear the state
            FILE_STATE = {
                exports:[],
                totp:[]
            }
            rs(false)
            return
        } 
        if(Object.keys(FILE_STATE).includes(type)){
            if(file_ref===undefined){
                FILE_STATE[type] = []
                rs(false)
                return
            }
            FILE_STATE[type].push(file_ref)
            rs(true)
            return
        } else {
            log(`Could not determine file group for type ${type}; File: ${file_ref?.name}`)
            rs(false)
            return
        }
    })
    s1ButtonCheck()
    return p
}

async function extractDataRaw(content, file_ref) {
    ftype = getFileType(content)
    switch (ftype) {
        case "json":
            if(JSONcontents?.db?.version === undefined){
                log(`Extracted encrypted JSON data from "${file_ref.name}"`)
                recordFileState("exports", file_ref)
                return {
                    isEncrypted: true,
                    data: JSONcontents
                }
            }
            log(`Extracted plain JSON data from "${file_ref.name}"`)
            recordFileState("exports", file_ref)
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
            log(`Extracted url data from "${file_ref.name}"`)
            recordFileState("exports", file_ref)
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

async function flipperizeEntries(inp) {
    if(inp.isEncrypted){
        return {
            error:"Export is encrypted. Decryption is not yet implemented"
        }
    }
    acc = ""
    data = []
    for (const entry of inp.data) {
        
        n = entry?.issuer!==""?entry?.issuer+": "+entry?.name:entry?.name
        s = entry?.info?.secret
        a = entry?.type?.toLowerCase()!=="steam"?ALGOMAP.from[entry?.info?.algo?.toUpperCase()]:ALGOMAP.from["STEAM"]
        dig = entry?.info?.digits
        dur = entry?.info?.period
        auto = entry?.flipper_automation!==undefined?entry?.flipper_automation:0
        obj = {
            TokenName:n,
            TokenSecret:s,
            TokenAlgo:a,
            TokenDigits:dig,
            TokenDuration:dur,
            TokenAutomationFeatures:auto
        }
        data.push(obj)
        if (entry.error) {
            continue
        }
        acc += `${Object.keys(obj).map(e=>{return `${e}: ${obj[e]}`}).join("\n")}`
    }
    return {plain:acc, data:data}
}

async function readTotpConfigHeader(file) {
    const reader = new FileReader();
    HEADER = JSON.parse(JSON.stringify(DEFAULTS))
    recordFileState("totp")
    reader.addEventListener('load', (event) => {
        document.getElementById(`drag${zone}0`).style.display = 'none'
        document.getElementById(`drag${zone}1`).style.display = 'none'
        progress =  document.getElementById(`drag${zone}2`)
        progress.innerHTML = `<div class="pad"><span id="loadtext0">LOADED ${shorten(file.name, 12, 6)}</span></div>`
        progress.style.display = 'flex'

        content = event?.target?.result
        expected_keys = Object.keys(HEADER)
        for (const l of content.split(new RegExp(`\n`))) {
            groups = [...l.matchAll(totpconfigReg)][0]
            if(groups===null || groups==undefined || groups?.length<2){
                continue
            }
            k = groups[1].trim()
            v = groups[2].trim()
            if(!expected_keys.includes(k)){
                continue
            }
            HEADER[k] = v
        }
        if(HEADER.Crypto === undefined || HEADER.Salt === undefined || HEADER.Crypto === null || HEADER.Salt === null){
            missing_headers = Object.keys(HEADER).reduce((a,e)=>{return a+((HEADER[e] === undefined || HEADER[e] === null)?` ${e}`:"")},"").trim().split(" ").join(', ')
            log(`Missing Crypto or Salt headers. Missing: ${missing_headers}`, "error")
            progress.innerHTML = `<div class="pad"><span id="loadtext0">ERROR PARSING ${shorten(file.name, 12, 6)}</span></div>`
        } else{
            log(`Loaded and parsed "${file.name}" file as totp.conf`)
            recordFileState("totp", file)
        }

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

async function toggleLogs() {
    document.getElementsByClassName("log-dropdown")[0].classList.toggle("log-hide")
    document.getElementById("log_icon").classList.toggle("icon-flip")
}

// Show screen 1 continue button only when at least one file for each file group was loaded
async function s1ButtonCheck() {
    file_groups = Object.keys(FILE_STATE)
    if(file_groups.reduce((a,e)=>{return a+(FILE_STATE[e].length>0?1:0)},0)===file_groups.length){
        // show screen 1 continue button
        document.getElementById("s1_r").classList.remove("btn-hide")
    } else {
        // hide screen 1 continue button
        document.getElementById("s1_r").classList.add("btn-hide")
    }
}

async function s1ButtonContinue() {
    transitionToScreen(2);
    updateHeaderUI(HEADER);
    unlockParams(false);
    updateTokensUI(TOKEN_ENTRIES);
}

async function transitionToScreen(screen_id) {
    screens = [1,2,3]
    for (const sc_id of screens) {
        s = document.getElementById(`screen${sc_id}`)
        if(!s){
            continue
        }
        s.classList.add("screen-disabled")
    }
    await sleep(300)
    s = document.getElementById(`screen${screen_id}`)
    if(!s){
        // fallback
        s = document.getElementById(`screen1`)
    }
    s.classList.remove("screen-disabled")

}

function generateInput(id, type, isProtected, value, default_value, set) {
    if(set!==undefined){
        // generate select
        ops = []
        for (const op of set) {
            selected = (value+"" == op.value+"")?` selected`:""
            ops.push(`<option value="${op.value}"${selected}>${op.label}</option>`)
        }
        dis = (isProtected===true)?` select-disabled`:""
        return `<div class="custom-select${dis}"><select id="${id}">${ops.join(`\n`)}</select></div>`

    } else {
        // generate input
        t = (type==="number" || type==="int" || type==="float")?"number":"text"
        q = (type==="number" || type==="int" || type==="float")?"":"\""
        s = (type==="float")?` min=-12.75 max=12.75 step=0.25`:""
        d = (isProtected===true)?` disabled="true"`:""
        v = (value!==undefined && value!==null)?` value=${q}${value}${q} placeholder="${default_value}"`:` placeholder="${default_value}"`
        return `<input type="${t}" id="${id}"${v}${s}${d}></input>`
    }
}

function updateHeaderUI(h) {
    entries = []
    ids = []
    force_user_inputted_tz = false
    for (const k of Object.keys(h)) {
        isExpected = Object.keys(TYPEINFO.totpconfig.header).includes(k)
        localized = (Object.keys(LOCALIZATION.totpconf).includes(k))?LOCALIZATION.totpconf[k]:k
        
        var v
        if(isExpected){
            ref = TYPEINFO.totpconfig.header[k]
            v = generateInput(k, ref.type, ref.protected, h[k], (ref.default==undefined || ref.default==null)? "&lt;missing value&gt;": ref.default, ref.set)
        } else {
            v = generateInput(k, "string", false, h[k], "&lt;unknown&gt;", undefined)
        }
        ids.push(k)

        entries.push(`<div class="entry"><div class="entry-label"><span>${localized}</span></div><div class="entry-value">${v}</div></div>`)
    }
    document.getElementById("ui_header").innerHTML = `<div class="entries">${entries.join(`\n`)}</div>`
    
    // update custom selects
    setDropdowns()
}

async function unlockParams(state, back) {
    b = document.getElementById("params_toggle")
    switch (state) {
        case true:
            // unlock params

            // unlock selectors
            for (const sel of document.getElementsByClassName("custom-select")) {
                sel.classList.remove("select-disabled")
            }

            // unlock inputs
            for (const sel of document.getElementsByTagName("input")) {
                sel.disabled = false
            }

            b.classList.remove("btn-danger")
            b.getElementsByTagName("span")[0].innerHTML = "LOCK SYSTEM PARAMETERS"
            b.getElementsByTagName("img")[0].src = "./icons/lock.svg"
            b.onclick = () =>{
                unlockParams(false)
            }
            PARAMS_LOCKED = false
            // hide alert
            await hideAlert("unlock_alert")
            break;
        case false:
            if(back){
                // hide alert
                await hideAlert("unlock_alert")
            } else {
                if(!PARAMS_LOCKED){
                    // lock params
                    // lock selects
                    for (const sel of document.getElementsByClassName("custom-select")) {
                        id = sel.getElementsByTagName("select")[0]?.id
                        if(id===undefined){
                            continue
                        }
                        if(TYPEINFO.totpconfig.header[id]?.protected || TYPEINFO.totpconfig.entry[id]?.protected){
                            sel.classList.add("select-disabled")
                        }
                    }

                    // lock inputs
                    for (const sel of document.getElementsByTagName("input")) {
                        if(sel.id===undefined){
                            continue
                        }
                        if(TYPEINFO.totpconfig.header[sel.id]?.protected || TYPEINFO.totpconfig.entry[sel]?.protected){
                            sel.disabled = true
                        }
                    }
                }
                b.classList.add("btn-danger")
                b.getElementsByTagName("span")[0].innerHTML = "UNLOCK SYSTEM PARAMETERS"
                b.getElementsByTagName("img")[0].src = "./icons/unlock.svg"
                b.onclick = ()=>{
                    unlockParams()
                } 
                PARAMS_LOCKED = true
            }
            
            break;
    
        default:
            //show alert
            document.getElementById("alert_target").innerHTML = `
            <div class="alert-areablock">
            <div id="unlock_alert" class="alert alert-show">
                <div class="alert-header"><div class="icon"><img src="./icons/warning.svg"> </div><span>WARNING</span></div>
                <div class="alert-content">
                    <i><p>It is dangerous to go... at all!</p></i>
                    <p>You are attempting to unlock parameters set by the Flipper Authenticator itself. Those settings are not meant to be changed manually and  have been locked to prevent accidental loss of data.</p>
                    <p>Changing those parameters could lead to incorrect code generation, failure to open the app, backup system failure, complete config reset, inability to enter the pin, token corruption or complete system hault/crash.</p>
                    <p>To safely change most of them, open the settings screen in the Flipper Authenticator by pressing the "OK" button. To safely change some settings you would need to use Flipper CLI. Please consult the manual over at <a target="_blank" href="https://github.com/akopachov/flipper-zero_authenticator/blob/master/docs/conf-file_description.md">The Official GitHub Repo</a> to make sure nothing would be corrupted.</p>
                    <p>Only change those settings manually if you completely understand what you are doing.</p>
                    <p>Are you sure you want to proceed?</p>
                </div>
                <div class="alert-buttons">
                    <div class="button btn-danger" onclick="unlockParams(true)"><div class="icon"><img src="./icons/unlock.svg"></div><span>YES, DO AS I SAY</span></div>
                    <div class="button" onclick="unlockParams(false, true)"><span>NO, GO BACK</span></div>
                </div>
            </div>
        </div>
            `
            break;
    }

}


function updateTokensUI(tokens) {
    tokens_flat = tokens.flat()
    targ = document.getElementById("ui_tokens")
    targ.innerHTML = ``
    acc = ``
    for (const i in tokens_flat) {
        acc+=`${genTokenEntry(tokens_flat[i], i)}`
    }
    targ.innerHTML = acc
    // update custom selects
    setDropdowns()
}

function genTokenEntry(data, token_id) {
    // @TODO: simplify this mess
    return `<div class="bounding-box" id="eid_${token_id}">
    <div>
        <div class="move-btn del-btn" onclick="deleteEntry(this)"><div class="icon icon-red"><img src="./icons/trash.svg"></div></div>
        <div class="move-btn" onclick="moveBox(${token_id}, -1)"><div class="icon"><img src="./icons/arrow.svg"></div></div>
        <div class="move-btn" onclick="moveBox(${token_id}, 1)"><div class="icon icon-flip"><img src="./icons/arrow.svg"></div></div>
    </div>
    <div class="entries">
        <div class="entry">
            <div class="entry-label"><span>${LOCALIZATION.totpconf.TokenName}</span></div>
            <div class="entry-value entry-long">
            ${generateInput(`${token_id}_TokenName`, TYPEINFO.totpconfig.entry.TokenName.type, TYPEINFO.totpconfig.entry.TokenName.protected, data.TokenName, TYPEINFO.totpconfig.entry.TokenName.default)}
            </div>
        </div>
        <div class="entry">
            <div class="entry-label"><span>${LOCALIZATION.totpconf.TokenSecret}</span></div>
            <div class="entry-value entry-long">
            ${generateInput(`${token_id}_TokenSecret`, TYPEINFO.totpconfig.entry.TokenSecret.type, TYPEINFO.totpconfig.entry.TokenSecret.protected, data.TokenSecret, TYPEINFO.totpconfig.entry.TokenSecret.default)}
            </div>
        </div>
        <div class="entry entry-cramp">
            <div class="entry-label"><span>${LOCALIZATION.totpconf.TokenAlgo}</span></div>
            <div class="entry-value entry-short">
            ${generateInput(`${token_id}_TokenAlgo`, TYPEINFO.totpconfig.entry.TokenAlgo.type, TYPEINFO.totpconfig.entry.TokenAlgo.protected, data.TokenAlgo, TYPEINFO.totpconfig.entry.TokenAlgo.default, TYPEINFO.totpconfig.entry.TokenAlgo.set)}
            </div>
        </div>
        <div class="entry entry-cramp">
            <div class="entry-label"><span>${LOCALIZATION.totpconf.TokenDigits}</span></div>
            <div class="entry-value entry-short">
            ${generateInput(`${token_id}_TokenDigits`, TYPEINFO.totpconfig.entry.TokenDigits.type, TYPEINFO.totpconfig.entry.TokenDigits.protected, data.TokenDigits, TYPEINFO.totpconfig.entry.TokenDigits.default, TYPEINFO.totpconfig.entry.TokenDigits.set)}
            </div>
        </div>
        <div class="entry entry-cramp">
            <div class="entry-label"><span>${LOCALIZATION.totpconf.TokenDuration}</span></div>
            <div class="entry-value entry-short">
            ${generateInput(`${token_id}_TokenDuration`, TYPEINFO.totpconfig.entry.TokenDuration.type, TYPEINFO.totpconfig.entry.TokenDuration.protected, data.TokenDuration, TYPEINFO.totpconfig.entry.TokenDuration.default, TYPEINFO.totpconfig.entry.TokenDuration.set)}
            </div>
        </div>
        <div class="entry entry-cramp">
            <div class="entry-label"><span>${LOCALIZATION.totpconf.TokenAutomationFeatures}</span></div>
            <div class="entry-value">
            ${generateInput(`${token_id}_TokenAutomationFeatures`, TYPEINFO.totpconfig.entry.TokenAutomationFeatures.type, TYPEINFO.totpconfig.entry.TokenAutomationFeatures.protected, (
                TYPEINFO.totpconfig.entry.TokenAutomationFeatures.set.map(x=>x.value).indexOf(Number(data.TokenAutomationFeatures))
            ), TYPEINFO.totpconfig.entry.TokenAutomationFeatures.default, TYPEINFO.totpconfig.entry.TokenAutomationFeatures.set)}
                </div>
        </div>
    </div>
</div>`

}

function getLastValidEID() {
    a = [...document.getElementsByClassName("entries")].map(e=>e?.parentElement?.id).sort()
    if(a.length===0){
        return -1
    } else {
        return Number(a[a.length-1].split("_")[1])
    }
}

function moveBox(id, dir) {
    dom_arr = document.getElementById("ui_tokens").children
    boundary = dom_arr.length -1
    pointer = [...dom_arr].indexOf(document.getElementById(`eid_${id}`))
    if(pointer+dir>boundary || pointer+dir<0){
        // don't move if there is no spot
        return
    }

    // save input changes to value=x for easy swap
    for (var ent of [...dom_arr[pointer].children[1].children, ...dom_arr[pointer+dir].children[1].children]){
        if(ent?.children?.item(1)?.children?.item(0)?.tagName?.toUpperCase() === "INPUT"){
            ent.children[1].children[0].setAttribute("value",  ent?.children?.item(1)?.children?.item(0).value)
        }
    }

    // swap items
    t = dom_arr[pointer].outerHTML
    dom_arr[pointer].outerHTML = dom_arr[pointer+dir].outerHTML
    dom_arr[pointer+dir].outerHTML = t

    // restore onclick listeners for dropdowns
    for (const ent of [...dom_arr[pointer].children[1].children, ...dom_arr[pointer+dir].children[1].children]) {
        e = ent?.children?.item(1)?.children?.item(0)?.children?.item(1)
        if(e?.classList?.contains("select-selected")){
            e.addEventListener("click", function (x) {
                selBoxClick(x, this)
            });
        }
    }
    
}

function addTokenBox() {
    l = document.getElementById("ui_tokens")
    var child = document.createElement('div');
    child.innerHTML = genTokenEntry(
        {
            TokenDuration: 30,
            TokenDigits: 6
        }, getLastValidEID()+1
    );
    child = child.firstChild;
    l.appendChild(child);

    // update dropdowns
    setDropdowns()
}

function deleteEntry(t) {
    t.parentElement.parentElement.remove()
}

async function tz_alert(param) {
    switch (param) {
        case "force":
            force_user_inputted_tz = true
            break;
        case "auto":
            document.getElementById("Timezone").value = checkTimezoneOffset().set_to
            break;
    
        default:
            // go back was pressed
            break;
    }
    // close alert regardless
    await hideAlert("tz_alert")
    return
}

async function export_alert(forceExport) {
    // close alert
    await hideAlert("export_alert")
    if(forceExport){
        // go straight to export
        s2Export(ALL_TOKEN_ENTRIES)
    }
    return
}

async function tryExport() {

    // check header, only time as unlocking the parameters has its own warning
    tz = checkTimezoneOffset()
    if(tz.error!==undefined && tz.alert){
        // show alert and exit
        document.getElementById("alert_target").innerHTML = `
        <div class="alert-areablock">
        <div id="tz_alert" class="alert alert-show">
            <div class="alert-header"><div class="icon"><img src="./icons/warning.svg"> </div><span>WARNING</span></div>
            <div class="alert-content">
                ${tz.error}
            </div>
            <div class="alert-buttons">
                <div class="button btn-danger" onclick="tz_alert('force')"><span>FORCE MY VALUE</span></div>
                <div class="button" onclick="tz_alert('auto')"><span>SET AUTOMATICALLY</span></div>
                <div class="button" onclick="tz_alert()"><span>GO BACK</span></div>
            </div>
        </div>
    </div>
        `
        return
    }


    VALID_FOR_EXPORT = []
    invalid_entries = []
    ALL_TOKEN_ENTRIES = []

    for (const entry of document.getElementById("ui_tokens").getElementsByClassName("entries")) {
        // get plain id for easy value grab
        id = Number(entry.parentElement.id.split("_")[1])
        entry_out = {}
        a_out = {}
        inv = false
        for (const k of Object.keys(TYPEINFO.totpconfig.entry)) {
            elem = document.getElementById(`${id}_${k}`)
            if(!elem){
                continue
            }
            v = elem.value
            a_out[k] = v || ""
            if(v===undefined || v===""){
                invalid_entries.push({
                    id:id,
                    reason:`Missing ${LOCALIZATION.totpconf[k]}`
                })
                inv = true
                continue
            } 
            entry_out[k] = v
        }
        if(JSON.stringify(a_out)==="{}"){
            continue
        }
        ALL_TOKEN_ENTRIES.push(a_out)
        if(!inv){
            VALID_FOR_EXPORT.push(entry_out)
        }
    }

    showAlert = false
    if(invalid_entries.length>0){
        log("Some entries contain invalid or incomplete data", "WARNING")
        showAlert = true
    }

    if(VALID_FOR_EXPORT.length===0){
        log("There are no valid entries to export", "WARNING")
        showAlert = true
    }


    if(showAlert){
        //show alert
        document.getElementById("alert_target").innerHTML = `
        <div class="alert-areablock">
        <div id="export_alert" class="alert alert-show">
            <div class="alert-header"><div class="icon"><img src="./icons/warning.svg"> </div><span>WARNING</span></div>
            <div class="alert-content">
                <p>You have provided incomplete token information.</p>
                <p>Entries valid for export: ${VALID_FOR_EXPORT.length}</p>
                <p>Invalid entries: ${invalid_entries.length}</p>
                <p>Check the logs or outlined fields for more info.</p>
                <p>You can still export the data as-is. However, the app might behave unpredictably and you might loose your data.</p>
                <p>Are you sure you want to proceed?</p>
            </div>
            <div class="alert-buttons">
                <div class="button btn-danger" onclick="s2Export(ALL_TOKEN_ENTRIES)"><div class="icon"><img src="./icons/file.svg"></div><span>YES, DO AS I SAY</span></div>
                <div class="button" onclick="hideAlert('export_alert')"><span>NO, GO BACK</span></div>
            </div>
        </div>
    </div>
        `
    } else {
        s2Export(VALID_FOR_EXPORT)
    }
    

}

async function hideAlert(id) {
    if(!document.getElementById(id)){
        return
    }
    document.getElementById(id).classList.remove("alert-show")
    document.getElementById(id).classList.add("alert-hide")
    await sleep(800)
    // clear alerts and bgs
    document.getElementById("alert_target").innerHTML = ``
    return
}

function checkTimezoneOffset() {
    to = -1 * new Date().getTimezoneOffset()
    flipper_tz = (to/60).toFixed(5)

    if(to%15!==0){
        log("Timezone Offset: Your current timezone offset is not supported by the Flipper Application User Interface. Proceed with caution.", "WARNING")
    }

        
    header_tz_raw = document.getElementById("Timezone").value

    if(header_tz_raw==""){
        return {
            alert: true,
            set_to:flipper_tz,
            error: "<p>Timezone Offset: You have not specified your timezone offset.</p><p>Do you want to automatically fill this field in with your current timezone offset taken from your current system time?</p>"
        }
    }

    if(Number(header_tz_raw)!==Number(flipper_tz) && !force_user_inputted_tz){
        return {
            alert: true,
            set_to: flipper_tz,
            error: "<p>Timezone Offset: Your current timezone does not match the one specified in global settings.</p> <p>Do you want to automatically fill this field in with your current timezone offset taken from your current system time?</p>"
        }
    }

    return true
}

async function s2Export(entries) {
    await hideAlert("export_alert")
    transitionToScreen(3)
    export_contents = ""
    // build header
    export_contents += Object.keys(TYPEINFO.totpconfig.header).map(e=>`${e}: ${document.getElementById(e).value.trim()}`).join("\n")+"\n"
    // build entries
    for (const e of entries) {
        export_contents += Object.keys(TYPEINFO.totpconfig.entry).map(k=>`${k}: ${e[k]?.trim() || ""}`).join("\n")+"\n"
    }
    document.getElementById("file_edit").value = export_contents
    // console.log(export_contents)
    return export_contents
}

async function s3Download() {
    const file = new File(document.getElementById("file_edit").value.split("/n") || [], 'totp.conf', {
        type: 'text/plain',
    })
      
    const link = document.createElement('a')
    const url = URL.createObjectURL(file)
    
    link.href = url
    link.download = file.name
    document.body.appendChild(link)
    link.click()
    
    document.body.removeChild(link)
    window.URL.revokeObjectURL(url)
}

async function copyToClipboard() {
    var copyText = document.getElementById("file_edit");

    // Select the text field
    copyText.select();
    copyText.setSelectionRange(0, 999999); // For mobile devices

    navigator.clipboard.writeText(copyText.value);
}

// Custom dropdowns setup
/* Look for any elements with the class "custom-select": */
function setDropdowns() {
    x = document.getElementsByClassName("custom-select");
    l = x?.length || 0;
    for (i = 0; i < l; i++) {

        if (x[i].getElementsByClassName("select-selected").length!==0) {
            // custom select exists, ignore
            continue
        }
        setupCustomSelect(x[i].getElementsByTagName("select")[0], x)
    }
}
setDropdowns()

function setupCustomSelect(selElmnt, x) {
    // Safeguard if element doesn't exist
    if(selElmnt===undefined || selElmnt?.length ===undefined){
        return
    }

    if(x===undefined){
        x = document.getElementsByClassName("custom-select")
    }

    ll = selElmnt.length;
    /* For each element, create a new DIV that will act as the selected item: */
    a = document.createElement("DIV");
    a.setAttribute("class", "select-selected");
    a.innerHTML = selElmnt.options[selElmnt.selectedIndex].innerHTML;
    x[i].appendChild(a);
    /* For each element, create a new DIV that will contain the option list: */
    b = document.createElement("DIV");
    b.setAttribute("class", "select-items select-hide");
    for (j = 0; j < ll; j++) {
        /* For each option in the original select element,
        create a new DIV that will act as an option item: */
        c = document.createElement("DIV");
        c.innerHTML = selElmnt.options[j].innerHTML;
        c.setAttribute("onclick", "clickSelectOpt(this)")
        b.appendChild(c);
    }
    x[i].appendChild(b);
    a.addEventListener("click", function (e) {
        selBoxClick(e, this)
    });
}

function selBoxClick(e, t) {
    /* When the select box is clicked, close any other select boxes,
    and open/close the current select box: */
    e.stopPropagation();
    closeAllSelect(t);
    t.nextSibling.classList.toggle("select-hide");
    t.classList.toggle("select-arrow-active");
}

function clickSelectOpt(t) {
    /* When an item is clicked, update the original select box,
        and the selected item: */
        var y, i, k, s, h, sl, yl;
        s = t.parentNode.parentNode.getElementsByTagName("select")[0];
        sl = s.length;
        h = t.parentNode.previousSibling;
        for (i = 0; i < sl; i++) {
          if (s.options[i].innerHTML == t.innerHTML) {
            s.selectedIndex = i;
            h.innerHTML = t.innerHTML;
            y = t.parentNode.getElementsByClassName("same-as-selected");
            yl = y.length;
            for (k = 0; k < yl; k++) {
              y[k].removeAttribute("class");
            }
            t.setAttribute("class", "same-as-selected");
            break;
          }
        }
        h.click();
}

function closeAllSelect(elmnt) {
  /* A function that will close all select boxes in the document,
  except the current select box: */
  var x, y, i, xl, yl, arrNo = [];
  x = document.getElementsByClassName("select-items");
  y = document.getElementsByClassName("select-selected");
  xl = x?.length || 0;
  yl = y?.length || 0;
  for (i = 0; i < yl; i++) {
    if (elmnt == y[i]) {
      arrNo.push(i)
    } else {
      y[i].classList.remove("select-arrow-active");
    }
  }
  for (i = 0; i < xl; i++) {
    if (arrNo.indexOf(i)) {
      x[i].classList.add("select-hide");
    }
  }
}


/* If the user clicks anywhere outside the select box,
then close all select boxes: */
document.addEventListener("click", closeAllSelect);