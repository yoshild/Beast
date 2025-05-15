def response(flow):
    if flow.request.path.startswith("/?q="):
        with open("/tmp/blocks_log.txt", "a") as f:
            f.write("=== Request: {}\n".format(flow.request.url))
            f.write("Response length: {}\n".format(len(flow.response.raw_content)))
            f.write("Hex: {}\n".format(flow.response.raw_content[:32].hex()))
            f.write("\n")

