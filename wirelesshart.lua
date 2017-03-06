-- wihart dissector
-- this was taken from Sam Roberts post on the wireshark-dev list
-- https://www.wireshark.org/lists/wireshark-dev/201107/msg00040.html
--[[
TODO:

- decode next level
- grok the protocol flow
- version

- libnet bugfix

OPTIONAL:

- new column for msg type

]]

local wihart = Proto("wihart", "Wireless HART")

local floor = math.floor
local function bxor (a,b)
    local r = 0
    for i = 0, 31 do
        local x = a / 2 + b / 2
        if x ~= floor (x) then
            r = r + 2^i
        end
        a = floor (a / 2)
        b = floor (b / 2)
    end
    return r
end
local function band (a,b) return ((a+b) - bxor(a,b))/2 end

local f = wihart.fields

local eui64 = {[0x0]="no", "yes"}
local priority = { [0] = "alarm", "normal", "process data", "command" }
local netkey = { [0] = "false", "true" }
local pkttype = { [0] = "ack", "advertise", "keep alive", "disconnect", [7] = "data" }

f.fortyone             = ProtoField.uint8("wihart.fortyone", "fortyone", base.HEX)
f.addrspec_b7          = ProtoField.uint8("wihart.addrspec.b7", "bit7", base.DEC, nil, 0x80) -- always 1
f.addrspec_b3          = ProtoField.uint8("wihart.addrspec.b3", "bit3", base.DEC, nil, 0x08) -- always 1
f.addrspec_dst64       = ProtoField.uint8("wihart.addrspec.dst64", "dst64", base.DEC, eui64, 0x40)
f.addrspec_src64       = ProtoField.uint8("wihart.addrspec.src64", "src64", base.DEC, eui64, 0x04)
f.seqno                = ProtoField.uint8("wihart.seqno", "seqno", base.DEC)
f.netid                = ProtoField.uint16("wihart.netid", "netid", base.HEX)
f.dstaddr              = ProtoField.uint16("wihart.dstaddr", "dstaddr", base.HEX)
f.dstaddr64            = ProtoField.uint64("wihart.dstaddr64", "dstaddr", base.HEX)
f.srcaddr              = ProtoField.uint16("wihart.srcaddr", "srcaddr", base.HEX)
f.srcaddr64            = ProtoField.uint64("wihart.srcaddr64", "srcaddr", base.HEX)
f.dlpduspec_priority   = ProtoField.uint8( "wihart.dlpduspec.priority", "priority", base.HEX, priority, 0x30)
f.dlpduspec_netkey     = ProtoField.uint8( "wihart.dlpduspec.netkey", "network key", base.DEC, netkey, 0x8)
f.dlpduspec_type       = ProtoField.uint8("wihart.dlpduspec.pkttype", "packet type", base.HEX, pkttype, 0x07)
f.dlpdudata            = ProtoField.bytes("wihart.dlpdudata", "dlpdudata")
f.mic                  = ProtoField.uint32("wihart.mic", "message integrity code", base.HEX)

-- advertise
f.adv_slot             = ProtoField.uint64("wihart.advertise.slot", "absolute slot number", base.DEC)
f.adv_joinctl          = ProtoField.uint8("wihart.advertise.joinctl", "join control", base.HEX)
f.adv_mapsz            = ProtoField.uint8("wihart.advertise.chanmapsz", "channel map size", base.DEC)
f.adv_map              = ProtoField.bytes("wihart.advertise.chanmap", "channel map")
f.adv_graphid          = ProtoField.uint16("wihart.advertise.graphid", "graph id", base.HEX)
f.adv_framecnt         = ProtoField.uint8("wihart.advertise.superframecount", "number of superframes", base.DEC)
f.adv_frameid          = ProtoField.uint8("wihart.advertise.frameid", "superframe id", base.DEC)
f.adv_framesz          = ProtoField.uint16("wihart.advertise.framesz", "superframe number of slots", base.DEC)
f.adv_linkcnt          = ProtoField.uint8("wihart.advertise.linkcnt", "number of links", base.DEC)
f.adv_linkjoinslot     = ProtoField.uint16("wihart.advertise.linkslot", "link join slot", base.DEC)
f.adv_linkjoinbits     = ProtoField.uint8("wihart.advertise.linkbits", "link join bits(6:xmit,5-0:chanoffset)", base.HEX)

-- ack
local ackcodes = {
     [0] = "success",
    [61] = "no buffers available",
    [62] = "no alarm/event buffers available",
    [63] = "priority too low",
}

f.ack_code             = ProtoField.uint8("wihart.ack.code", "response code", base.DEC, ackcodes)
f.ack_timeadj          = ProtoField.int16("wihart.ack.timeadj", "time adjustment (usec)", base.DEC)

-- data => network layer PDU
f.nwk_control          = ProtoField.uint8("wihart.nwk.control", "control field", base.HEX)
f.nwk_control_dst64    = ProtoField.uint8("wihart.nwk.control.dst64", "dst64", base.DEC, eui64, 0x80)
f.nwk_control_src64    = ProtoField.uint8("wihart.nwk.control.src64", "src64", base.DEC, eui64, 0x40)
f.nwk_ttl              = ProtoField.uint8("wihart.nwk.ttl", "time to live hop count", base.DEC)
f.nwk_asn              = ProtoField.uint16("wihart.nwk.asn", "snippet of abs slot number", base.HEX)
f.nwk_graphid          = ProtoField.uint16("wihart.nwk.graphid", "graph id", base.HEX)
f.nwk_dstaddr          = ProtoField.uint16("wihart.nwk.dstaddr", "dstaddr", base.HEX)
f.nwk_dstaddr64        = ProtoField.uint64("wihart.nwk.dstaddr64", "dstaddr", base.HEX)
f.nwk_srcaddr          = ProtoField.uint16("wihart.nwk.srcaddr", "srcaddr", base.HEX)
f.nwk_srcaddr64        = ProtoField.uint64("wihart.nwk.srcaddr64", "srcaddr", base.HEX)

local addr64

function wihart.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol = "WiHART"

    if buffer(0,1):uint() ~= 0x41 then
        -- I'ts not wihart, I think we were getting ZigBee beacon requests,
        -- dissection will fail, so stop with this.
        pinfo.cols.protocol = "UNKNOWN"
        return
    end

    local subtree = tree:add(wihart, buffer(), "WiHART DLPDU")
    subtree:add(f.fortyone, buffer(0,1))

    local addrtree = subtree:add(wihart, buffer(1,1), string.format("addrspec: 0x%x", buffer(1,1):uint()))
    local addrspec = buffer(1,1):uint()
    addrtree:add(f.addrspec_b7, buffer(1,1))
    addrtree:add(f.addrspec_dst64, buffer(1,1))
    addrtree:add(f.addrspec_b3, buffer(1,1))
    addrtree:add(f.addrspec_src64, buffer(1,1))

    subtree:add(f.seqno, buffer(2,1))
    subtree:add(f.netid, buffer(3,2))

    local pos = 5
    local function doaddr(kind, mask, prefix, tree)
        -- print(kind, mask, prefix)
        tree = tree or subtree
        prefix = prefix or ""
        local b
        if band(addrspec, mask) == mask then
            b = buffer(pos,8)
            tree:add(f[prefix..kind.."addr64"], b)
            if not addr64 then -- FIXME
                addr64 = b:uint64()
            end
        else
            b = buffer(pos,2)
            tree:add(f[prefix..kind.."addr"], b)
        end
        pinfo.cols[kind] = tostring(b)
        pos = pos + b:len()
    end
    doaddr("dst", 0x40)
    doaddr("src", 0x04)

    print("============> addr64", addr64)

    local b = buffer(pos,1)
    pos = pos + 1
    local pkttree = subtree:add(wihart, b, string.format("dlpduspec: 0x%x", b:uint()))
    local dlpduspec = b:uint()
    pkttree:add(f.dlpduspec_priority, b)
    pkttree:add(f.dlpduspec_netkey, b)
    pkttree:add(f.dlpduspec_type, b)

    local priority = band(dlpduspec, 0x30)
    local netkey = band(dlpduspec, 0x8)
    local type = band(dlpduspec, 0x7)

    local datalen = buffer:len() - pos - 4
    local pdu = buffer(pos,datalen)
    local pduname = pkttype[type] or "UNKNOWN"

    pinfo.cols.info = pduname

    subtree:add(f.dlpdudata, pdu)
    subtree:add(f.mic, buffer(buffer:len() - 4, 4))

    local function add(tree, field, size)
        tree:add(field, buffer(pos, size))
        pos = pos + size
    end

    if pduname == "data" then
        local nwktree = tree:add(wihart, pdu, "WiHART NLPDU")

        addrspec = buffer(pos,1):uint()
        add(nwktree, f.nwk_control, 1)

        --local addrtree = subtree:add(wihart, buffer(1,1), string.format("addrspec: 0x%x", buffer(1,1):uint()))
        --addrtree:add(f.addrspec_dst64, buffer(1,1))
        --addrtree:add(f.addrspec_src64, buffer(1,1))

        add(nwktree, f.nwk_ttl, 1)
        add(nwktree, f.nwk_asn, 2)
        add(nwktree, f.nwk_graphid, 2)

        doaddr("dst", 0x80, "nwk_", nwktree)
        doaddr("src", 0x40, "nwk_", nwktree)
    end

    if pduname == "ack" then
        local acktree = tree:add(wihart, pdu, "WiHART ACK")
        add(acktree, f.ack_code, 1)
        add(acktree, f.ack_timeadj, 2)
    end

    if pduname == "advertise" then
        local advtree = tree:add(wihart, pdu, "WiHART ADVERTISE")

        add(advtree, f.adv_slot, 5)
        add(advtree, f.adv_joinctl, 1)
        local mapsz = math.ceil(buffer(pos, 1):uint() / 8)
        add(advtree, f.adv_mapsz, 1)
        add(advtree, f.adv_map, mapsz)
        add(advtree, f.adv_graphid, 2)
        local framecnt = buffer(pos, 1):uint()
        add(advtree, f.adv_framecnt, 1)

        -- I could make these look way better, by using subtrees and setting
        -- nice strings, but this is good enough for now.
        while framecnt > 0 do
            add(advtree, f.adv_frameid, 1)
            add(advtree, f.adv_framesz, 2)
            local linkcnt = buffer(pos, 1):uint()
            add(advtree, f.adv_linkcnt, 1)
            while linkcnt > 0 do
                add(advtree, f.adv_linkjoinslot, 2)
                add(advtree, f.adv_linkjoinbits, 1)
                linkcnt = linkcnt - 1
            end

            framecnt = framecnt - 1
        end

        assert(pos == buffer:len()-4)
    end

end

local wtap_encap = DissectorTable.get("wtap_encap")
-- 223 has now been assigned to DLT, see http://seclists.org/tcpdump/2009/q2/180
-- wtap_encap:add(wtap.USER0,wihart)
wtap_encap:add(223,wihart)
