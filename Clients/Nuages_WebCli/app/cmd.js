function CommandParser(str) {
    var args = [];
    var readingPart = false;
    var quoteStyle = false;
    var part = '';
    for(var i=0; i<str.length;i++){
        if(str.charAt(i) === ' ' && !readingPart) {
            if(part != ''){
                args.push(part);
            }
            part = '';
        } else {
            if( str.charAt(i) === quoteStyle){
                readingPart = !readingPart;
                quoteStyle = false;
            }
            else if((str.charAt(i) === '\"' || str.charAt(i) === '\'') && !readingPart) {
                readingPart = !readingPart;
                quoteStyle = str.charAt(i);
            } else {
                part += str.charAt(i);
            }
        }
    }
    args.push(part);
    return args;
}
function executeCommand(cmd){
    cmdArray = CommandParser(cmd, true);
    cmdArray = cmdArray.filter(function(element) {
        return element !== "";
    });
    if(cmdArray.length == 0){
        return;
    }
    else if(cmdArray[0].toLowerCase() == "!implant"){
        cmdArray.splice(1, 0, nuages.vars.globalOptions.implant);
        cmdArray[0]="!implants";
    }
    else if(cmdArray[0].toLowerCase() == "!shell"){
        cmdArray.splice(1, 0, "implant");
        cmdArray[0]="!setg";
    }
    if (cmdArray[0].toLowerCase() == "!login" && cmdArray.length > 1){
        term.passwordMode = true;
        term.setPromptline();
        nuages.vars.user = {email: cmdArray[1]};
    }
    else if (cmdArray[0].toLowerCase() == "cd"){
        if(nuages.vars.implants[nuages.vars.globalOptions.implant.substring(0.6)].supportedPayloads.includes("cd")){
            nuages.createJob(nuages.vars.globalOptions.implant, {type:"cd", options:{ path: nuages.vars.paths[nuages.vars.globalOptions.implant.substring(0.6)], dir:cmdArray.slice(1).join(" ")}});
        }
        else{
            nuages.createJob(nuages.vars.globalOptions.implant, {type:"cmd", options:{ path: nuages.vars.paths[nuages.vars.globalOptions.implant.substring(0.6)], cmd: "cmd /C \"FOR /F %i IN (\"\""+cmdArray.slice(1).join(" ")+"\"\") DO IF EXIST %~fi (echo %~fi)\"", cd:true}});
    }   }
    else if (cmdArray[0].toLowerCase() == "!options"){
        nuages.printOptions();
    }
    else if (cmdArray[0].toLowerCase() == "!modules"){
        if(cmdArray.length == 1){
            nuages.getModules();	
        }
        else if(cmdArray.length > 2 && cmdArray[1].toLowerCase() == "load"){
            nuages.modloadService.create({modulePath:cmdArray[2]}).catch((err) => {
                term.printError(err.message);
            });
        }
        else if(cmdArray.length > 2 && cmdArray[2].toLowerCase() == "del"){
            if(nuages.vars.modules[cmdArray[1].toLowerCase()]){
                    nuages.moduleService.remove(nuages.vars.modules[cmdArray[1].toLowerCase()]._id).catch((err) => {
                    term.printError(err.message);
                });
            }else{
                term.printError("Module not found");
            }
        }
    }
    else if (cmdArray[0].toLowerCase() == "!handlers"){
        if(cmdArray.length == 1){
            nuages.getHandlers();	
        }
        else if(cmdArray.length > 2 && cmdArray[1].toLowerCase() == "load"){
            nuages.handloadService.create({handlerPath:cmdArray[2]}).catch((err) => {
                term.printError(err.message);
            });
        }
        else if(cmdArray.length > 2 && cmdArray[2].toLowerCase() == "del"){
            if(nuages.vars.handlers[cmdArray[1].toLowerCase()]){
                    nuages.handlerService.remove(nuages.vars.handlers[cmdArray[1].toLowerCase()]._id).catch((err) => {
                    term.printError(err.message);
                });
            }else{
                term.printError("Handler not found");
            }
        }
    }else if (cmdArray[0].toLowerCase() == "!listeners"){
        if(cmdArray.length == 1){
            nuages.getListeners();	
        }
        else if(cmdArray.length > 2 && cmdArray[2].toLowerCase() == "del"){
            if(nuages.vars.listeners[cmdArray[1]]){
                    nuages.listenerService.remove(nuages.vars.listeners[cmdArray[1]]._id).catch((err) => {
                    term.printError(err.message);
                });
            }else{
                term.printError("Listener not found");
            }
        }
        else if(cmdArray.length > 2 && cmdArray[2].toLowerCase() == "stop"){
            if(nuages.vars.listeners[cmdArray[1]]){
                nuages.listenerStartService.create({id:nuages.vars.listeners[cmdArray[1]]._id, wantedStatus: 2}).catch((err) => {
                    term.printError(err.message);
                });
            }else{
                term.printError("Listener not found");
            }
        }
        else if(cmdArray.length > 2 && cmdArray[2].toLowerCase() == "start"){
            if(nuages.vars.listeners[cmdArray[1]]){
                nuages.listenerStartService.create({id:nuages.vars.listeners[cmdArray[1]]._id, wantedStatus: 3}).catch((err) => {
                    term.printError(err.message);
                });
            }else{
                term.printError("Listener not found");
            }
        }
        else if(cmdArray.length == 2){
            if(nuages.vars.listeners[cmdArray[1]]){
                    console.log(nuages.printListeners({mod:nuages.vars.listeners[cmdArray[1]]}));
                    nuages.printModuleOptions("handler",nuages.vars.listeners[cmdArray[1]].options);
            }else{
                term.printError("Listener not found");
            }
        }
    }
    else if(cmdArray[0] == "!run"){
        if(nuages.vars.moduletype=="module"){
            if(nuages.vars.modules[nuages.vars.module]){
                nuages.modrunService.create({moduleId: nuages.vars.modules[nuages.vars.module]._id, options: nuages.vars.moduleOptions, autorun: false}).catch((err) => {
                        term.printError(err.message);
                    });
                }else{
                    term.printError("Module not set");
                }
            }
        else if(nuages.vars.moduletype=="handler"){
            if(nuages.vars.handlers[nuages.vars.module]){
                nuages.listenerService.create({handlerId: nuages.vars.handlers[nuages.vars.module]._id, options: nuages.vars.moduleOptions}).then((run)=>{
                    nuages.listenerStartService.create({id:run._id, wantedStatus: 3}).catch((err) => {
                        term.printError(err.message);
                    });

                }).catch((err) => {
                        term.printError(err.message);
                    });
                }else{
                    term.printError("Handler not set");
                }
            }
        else{
            term.printError("You have nothing to run!");
        }
    }
    else if(cmdArray[0] == "!autorun"){
        if(nuages.vars.modules[nuages.vars.module]){
                nuages.modrunService.create({moduleId: nuages.vars.modules[nuages.vars.module]._id, options: nuages.vars.moduleOptions, autorun: true}).then(items => {nuages.getAutoruns()}).catch((err) => {
                    term.printError(err.message);
                });
            }else{
                term.logError("Module not set");
            }
    }
    else if(cmdArray[0] == "!autoruns"){
        if(cmdArray[1] == "clear"){
            nuages.clearAutoruns();
        } 
        else {nuages.getAutoruns();}
    }
    else if(cmdArray[0] == "!help" || cmdArray[0] == "?"){
        nuages.printHelp();
    }
    else if (cmdArray[0].toLowerCase() == "!use"){
        if(cmdArray.length > 1){
            if (nuages.vars.modules[cmdArray[1].toLowerCase()] !== undefined){
                nuages.vars.module = cmdArray[1].toLowerCase();
                nuages.vars.moduleOptions = nuages.vars.modules[cmdArray[1].toLowerCase()].options;
                if(nuages.vars.moduleOptions.implant && nuages.vars.implants[nuages.vars.globalOptions.implant]){
                    nuages.vars.moduleOptions.implant.value = nuages.vars.implants[nuages.vars.globalOptions.implant]._id;
                }
                nuages.vars.moduletype = "module";
            }else if(nuages.vars.handlers[cmdArray[1].toLowerCase()] !== undefined){
                nuages.vars.module = cmdArray[1].toLowerCase();
                nuages.vars.moduleOptions = nuages.vars.handlers[cmdArray[1].toLowerCase()].options;
                nuages.vars.moduletype = "handler";
            }
            else{
                term.logError("Module not found, did you load modules with '!modules load' ?");
            }	
        }
    }
    else if (cmdArray[0].toLowerCase() == "!get"){
        var arr = cmdArray[1].split("\\");
        var filename = arr[arr.length-1];
        arr = filename.split("/");
        filename = arr[arr.length-1];
        nuages.createJobWithUpload(nuages.vars.globalOptions.implant, {type:"upload", options:{ file: cmdArray[1], chunkSize: parseInt(nuages.vars.globalOptions.chunksize), path: nuages.vars.paths[nuages.vars.globalOptions.implant.substring(0.6)]}}, filename);
    }
    else if (cmdArray[0].toLowerCase() == "!put"){
        if(nuages.vars.files[cmdArray[1]] != undefined ||  cmdArray.length < 2){
            var file = cmdArray[2] ? cmdArray[2] : nuages.vars.files[cmdArray[1]].filename;
            nuages.createJob(nuages.vars.globalOptions.implant, {type:"download", options:{ file: file, filename: nuages.vars.files[cmdArray[1]].filename, file_id: nuages.vars.files[cmdArray[1]]._id, length: nuages.vars.files[cmdArray[1]].length, chunkSize: nuages.vars.files[cmdArray[1]].chunkSize, path: nuages.vars.paths[nuages.vars.globalOptions.implant.substring(0.6)]}});
        }else{
            term.printError("\r\n File not found");
        }
    }
    else if (cmdArray[0].toLowerCase() == "!files"){
        if(cmdArray.length < 2){
            nuages.getFiles();
        }else if(cmdArray[1].toLowerCase() == "upload" && cmdArray.length > 2){
            nuages.loadFile(cmdArray[2]); 
        }
        else if(cmdArray.length == 2){
            if (nuages.vars.files[cmdArray[1]] != undefined){
                term.writeln("\r\n" + nuages.printFiles({imp:nuages.vars.files[cmdArray[1]]}));
                term.prompt();
            }else{
                term.writeln("\r\n File not found");
                term.prompt();
            }
        }
        else if(cmdArray[2] == "del"){
            if (nuages.vars.files[cmdArray[1]] != undefined){
                nuages.fsService.remove(nuages.vars.files[cmdArray[1]]._id);
            }else{
                term.writeln("\r\n File not found");
                term.prompt();
            }
        }else if(cmdArray[2] == "download" && cmdArray.length > 3){
            nuages.downloadFile(cmdArray[1],cmdArray[3]);
        }
    }else if (cmdArray[0].toLowerCase() == "!jobs"){
        if(cmdArray.length < 2){
            nuages.getJobs();
        }else if(cmdArray.length == 3 && cmdArray[1].toLowerCase()=="search"){
            nuages.getJobs(cmdArray[2]);
        }
        else{
            if (nuages.vars.jobs[cmdArray[1]] != undefined){
                if(cmdArray.length == 4 && cmdArray[2].toLowerCase()=="save"){
                    nuages.saveTextToFile(nuages.vars.jobs[cmdArray[1]].result,cmdArray[3]);
                }else{
                    term.writeln("\r\n" + nuages.printJobs({imp:nuages.vars.jobs[cmdArray[1]]}));
                    term.writeln("\r\n" + nuages.vars.jobs[cmdArray[1]].result);
                }

            }else{
                term.printError("Job not found");
            }
        }
    }
    else if (cmdArray[0].toLowerCase() == "!implants"){
        if(cmdArray.length < 2){
            nuages.getImplants();
        }
        else if(cmdArray[1].toLowerCase() === "all"){
            nuages.implantService.find().then(implants => {
                for(var i=0; i< implants.data.length; i++){
                    cmdArray[1] = implants.data[i]._id.substring(0,6);
                    executeCommand(cmdArray.join(" "));
                }
            }).catch(err=>{
                term.printError(err);
            });
            
        }
        else if(cmdArray.length == 2){
            if (nuages.vars.implants[cmdArray[1]] != undefined){
                term.writeln("\r\n" + nuages.printImplants({imp:nuages.vars.implants[cmdArray[1]]}));
            }else{
                term.printError("Implant not found");
            }
        }
        else if(nuages.vars.implants[cmdArray[1]] == undefined){
            term.printError("Implant not found");
        }
        else if(cmdArray[2] == "del"){
            nuages.implantService.remove(nuages.vars.implants[cmdArray[1]]._id);
        }
        else if(cmdArray[2].toLowerCase() == "kill" || cmdArray[2].toLowerCase() == "exit"){
            nuages.createJob(cmdArray[1], {type: "exit", options: {}});
        }
        else if((cmdArray[2].toLowerCase() == "config" || cmdArray[2].toLowerCase() == "configure")){
            var tmpconfig = {};
            if(cmdArray.length >4 ){
                tmpconfig[cmdArray[3]] = cmdArray[4];
            }
            nuages.createJob(cmdArray[1], {type: "configure", options: {config:tmpconfig}});
        }
    }
    else if (cmdArray[0].toLowerCase() == "!setg" && cmdArray.length > 2){
        if(cmdArray[1].toLowerCase() == "implant"){
            if(nuages.vars.implants[cmdArray[2]]){
                nuages.vars.globalOptions["implant"] = cmdArray[2];
                if(nuages.vars.paths[cmdArray[2]] == undefined){
                    nuages.vars.paths[cmdArray[2]] = ".";
                }
            }else{
                term.printError("Implant not found");
            }
        }else{
            nuages.vars.globalOptions[cmdArray[1].toLowerCase()] = cmdArray[2];
        }     
    }
    else if (cmdArray[0].toLowerCase() == "!unsetg" && cmdArray.length > 1){
        nuages.vars.globalOptions[cmdArray[1].toLowerCase()] = "";
    }
    else if (cmdArray[0].toLowerCase() == "!unset" && cmdArray.length > 1){
        if(nuages.vars.moduleOptions[cmdArray[1].toLowerCase()] !== undefined){
                nuages.vars.moduleOptions[cmdArray[1].toLowerCase()].value = "";
        }else{
            term.printError("Option does not exist");
        }   
    }
    else if (cmdArray[0].toLowerCase() == "!set" && cmdArray.length > 2){
        if(nuages.vars.moduleOptions[cmdArray[1].toLowerCase()] !== undefined){
            if(cmdArray[1].toLowerCase() == "implant"){
                if(nuages.vars.implants[cmdArray[2]]){
                    nuages.vars.moduleOptions["implant"].value = nuages.vars.implants[cmdArray[2]]._id;
                }else{
                    term.printError("Implant not found");
                }
            }else if(cmdArray[1].toLowerCase() == "file"){
                if(nuages.vars.files[cmdArray[2]]){
                    nuages.vars.moduleOptions["file"].value = nuages.vars.files[cmdArray[2]]._id;
                }else{
                    term.printError("File not found");
                }
            }
            else{
                nuages.vars.moduleOptions[cmdArray[1].toLowerCase()].value = cmdArray[2];
            }
        }else{
            nuages.vars.moduleOptions[cmdArray[1].toLowerCase()] = {value: cmdArray[2], required: false};
        }     
    }
    else if (cmdArray[0].toLowerCase() == "!back"){
            nuages.vars.globalOptions["implant"]= "";     
        }
    else if(cmdArray[0].length > 0 && cmd[0] != "!"){
        nuages.createJob(nuages.vars.globalOptions.implant, {type:"cmd", options:{ path: nuages.vars.paths[nuages.vars.globalOptions.implant.substring(0.6)], cmd: cmd}});
    }else{
        term.printError("Invalid command, type !help for assistance");
    }
    return;
}
