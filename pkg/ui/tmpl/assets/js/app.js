$(document).ready(function () {

    $("#wsBtn").on("click", () => {
        const protocolPrefix = (window.location.protocol === 'https:') ? 'wss:' : 'ws:';
        const socket = new WebSocket(protocolPrefix + '//' + location.host + "/websocket");
        socket.onopen = () => {
            socket.send("ping")
        }

        socket.onmessage = (event) => {
            $("#wsResult").val(event.data)
            socket.close()
        }

        socket.onclose = (event) => {
            if (event.wasClean) {
                console.log(`[close] Connection closed cleanly, code=${event.code} reason=${event.reason}`);
            } else {
                console.log('[close] Connection died')
            }
        }
    })

    $("#loadIframeBtn").on("click", () => {
        $("#test-iframe").attr('src', $("#iframeInput").val())
    })

    $("#ajaxIframeBtn").on("click", () => {
        $.getJSON($("#ajaxInput").val(), (data, status, jqXHR) => {

            $("#ajaxResult").val(JSON.stringify(data))
            let body = []
            $("#ajaxHeadersResult").empty()
            jqXHR.getAllResponseHeaders().split("\n").forEach(header => {
                let kv = header.split(":")
                if (kv.length == 2) {
                    body.push('<tr><td class="col-2">' + kv[0] + '</td><td>' + kv[1] + '</td></tr>')
                }
            })
            $("#ajaxHeadersResult").append(body)

        });
    })

});


function createWebSocket() {

    return
}
