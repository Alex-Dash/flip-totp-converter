const urlReg = new RegExp(`otpauth:\\/\\/.*?\\/.*?$`, "gm")
const urlMainReg = new RegExp(`\\/\\/(.*?)\\/(.*?)((:(.*))|$)`)
const urlParamsReg = new RegExp(`([^&]+?)=([^&]+)`, "g")
const ALGOMAP = {
    to:["SHA1", "SHA256", "SHA512", "STEAM"],
    from:{
        "SHA1":0,
        "SHA256":1,
        "SHA512":2,
        "STEAM":3
    }
}

async function parseFileList(list) {
    for (const item of list) {
        readFileAsync(item)
    }
}

async function readFileAsync(path) {
    const reader = new FileReader();
    reader.addEventListener('load', (event) => {
        extractDataRaw(event?.target?.result).then(
            r=>flipperizeEntries(r).then(
                x=>console.log(x.data)
                )
            )
    });
    reader.readAsText(path);
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