function addItems(name, data) {
    var old = sessionStorage.getItem(name);
    if (old === null) {
        sessionStorage.setItem(name, data);
    } else {
        old = sessionStorage.getItem(name);
        sessionStorage.setItem(name, old + ',' + data);
    }
}

function addOthers(name, data) {
    var old = sessionStorage.getItem(name);
    if (old === null) {
        sessionStorage.setItem(name, data);
    } else {
        old = sessionStorage.getItem(name);
        sessionStorage.setItem(name, old + "," + data);
    }
}