import QtQuick
import QtQml.WorkerScript
import Quickshell.Io

// One agent's usage record, read straight off the data file that
// omarchy-agent-usage-update maintains. The panel never learns how the
// numbers were made — a record that appears in the usage directory is an
// agent, whoever wrote it.
Item {
  id: root
  visible: false

  property string agentId: ""
  property string path: ""
  property var record: null
  readonly property var dailyUsage: record && record.dailyUsage ? record.dailyUsage : null

  property int parseGeneration: 0
  property int pendingGeneration: 0
  property string pendingContent: ""
  property bool parserBusy: false

  // Main owns one parser for all its records: every WorkerScript runs its own
  // JavaScript engine, so a worker per record cost two dozen engines per bar.
  // Replies carry the record key; each record takes only its own.
  property WorkerScript parser: null
  readonly property string parserKey: agentId + "\n" + path

  Connections {
    target: root.parser
    function onReadyChanged() { root.dispatchParse() }
    function onMessage(message) {
      if (message.key !== root.parserKey) return
      root.parserBusy = false
      root.acceptParsedRecord(message.generation, message.record)
      root.dispatchParse()
    }
  }

  function reload() { recordFile.reload() }

  FileView {
    id: recordFile
    path: root.path
    watchChanges: true
    printErrors: false
    onFileChanged: reload()
    onLoaded: root.parse(text())
    onLoadFailed: {
      root.parseGeneration++
      root.pendingGeneration = 0
      root.pendingContent = ""
      root.record = null
    }
  }

  function parse(content) {
    pendingGeneration = ++parseGeneration
    pendingContent = String(content || "")
    dispatchParse()
  }

  function dispatchParse() {
    if (!parser || !parser.ready || parserBusy || pendingGeneration === 0) return
    parserBusy = true
    // WorkerScript cannot transport one string of 16 Mi characters or more.
    // Keep each part below that limit; join and parse only in the worker.
    var chunkSize = 1024 * 1024
    var chunks = []
    for (var offset = 0; offset < pendingContent.length; offset += chunkSize)
      chunks.push(pendingContent.slice(offset, offset + chunkSize))
    parser.sendMessage({ key: parserKey, generation: pendingGeneration, chunks: chunks })
    pendingGeneration = 0
    pendingContent = ""
  }

  function acceptParsedRecord(generation, parsed) {
    // A newer file read/removal wins over an older background result.
    if (generation !== parseGeneration) return
    if (record && parsed) {
      // Limit-only changes reuse the same compact usage objects and price cache.
      var fields = ["dailyUsage", "recentDays", "modelUsage"]
      for (var i = 0; i < fields.length; i++) {
        var key = fields[i]
        if (JSON.stringify(record[key]) === JSON.stringify(parsed[key]))
          parsed[key] = record[key]
      }
    }
    record = parsed
  }
}
