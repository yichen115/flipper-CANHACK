#include "mcp_can_2515.h"

// To read a register with SPI protocol
static bool read_register(FuriHalSpiBusHandle* spi, uint8_t address, uint8_t* data) {
    bool ret = true;
    uint8_t instruction[] = {INSTRUCTION_READ, address};
    furi_hal_spi_acquire(spi);
    ret = furi_hal_spi_bus_tx(spi, instruction, sizeof(instruction), TIMEOUT_SPI);
    ret = ret && furi_hal_spi_bus_rx(spi, data, 1, TIMEOUT_SPI);
    furi_hal_spi_release(spi);
    return ret;
}

// To read a register with SPI Protocol
static bool set_register(FuriHalSpiBusHandle* spi, uint8_t address, uint8_t data) {
    bool ret = true;
    uint8_t instruction[] = {INSTRUCTION_WRITE, address, data};
    furi_hal_spi_acquire(spi);
    ret = furi_hal_spi_bus_tx(spi, instruction, sizeof(instruction), TIMEOUT_SPI);
    furi_hal_spi_release(spi);
    return ret;
}

// To modify the value of one bit from a register
static bool
    modify_register(FuriHalSpiBusHandle* spi, uint8_t address, uint8_t mask, uint8_t data) {
    uint8_t instruction[] = {INSTRUCTION_BITMOD, address, mask, data};
    bool ret = true;
    furi_hal_spi_acquire(spi);
    ret = furi_hal_spi_bus_tx(spi, instruction, sizeof(instruction), TIMEOUT_SPI);
    furi_hal_spi_release(spi);
    return ret;
}

// To reset the MCP2515
bool mcp_reset(FuriHalSpiBusHandle* spi) {
    uint8_t buff[1] = {INSTRUCTION_RESET};
    bool ret = true;
    furi_hal_spi_acquire(spi);
    ret = furi_hal_spi_bus_tx(spi, buff, sizeof(buff), TIMEOUT_SPI);
    furi_hal_spi_release(spi);
    return ret;
}

// To get the MCP2515 status
bool mcp_get_status(FuriHalSpiBusHandle* spi, uint8_t* data) {
    uint8_t buff[1] = {INSTRUCTION_READ_STATUS};
    bool ret = true;
    furi_hal_spi_acquire(spi);
    ret =
        (furi_hal_spi_bus_tx(spi, buff, sizeof(buff), TIMEOUT_SPI) &&
         furi_hal_spi_bus_rx(spi, data, 1, TIMEOUT_SPI));
    furi_hal_spi_release(spi);
    return ret;
}

// This function works to get the Can Id from the buffer
void read_Id(FuriHalSpiBusHandle* spi, uint8_t addr, uint32_t* id, uint8_t* ext) {
    uint8_t tbufdata[4] = {0, 0, 0, 0};
    *ext = 0;
    *id = 0;

    read_register(spi, addr, tbufdata);

    *id = (tbufdata[MCP_SIDH] << 3) + (tbufdata[MCP_SIDL] >> 5);

    if((tbufdata[MCP_SIDL] & MCP_TXB_EXIDE_M) == MCP_TXB_EXIDE_M) {
        *id = (*id << 2) + (tbufdata[MCP_SIDL] & 0x03);
        *id = (*id << 8) + tbufdata[MCP_EID8];
        *id = (*id << 8) + tbufdata[MCP_EID0];
        *ext = 1;
    }
}

// get actual mode of the MCP2515
uint8_t get_mode(FuriHalSpiBusHandle* spi) {
    uint8_t data = 0;
    return read_register(spi, MCP_CANSTAT, &data) ? data & CANSTAT_OPM : 0xFF;
}

// compare if the chip is the same mode
bool is_mode(MCP2515* mcp_can, MCP_MODE mode) {
    uint16_t data = get_mode(mcp_can->spi);
    if(data == mode) return true;
    return false;
}

// To set a new mode
bool set_new_mode(MCP2515* mcp_can, MCP_MODE new_mode) {
    FuriHalSpiBusHandle* spi = mcp_can->spi;

    uint8_t read_status = 0;
    bool ret = false;

    uint8_t initial_mode = get_mode(spi);
    if(initial_mode == 0xFF) return false;
    if(initial_mode == new_mode) return true;

    if(initial_mode == MCP_SLEEP && new_mode != MCP_SLEEP) {
        uint8_t wake_up_enabled = 0;
        read_register(spi, MCP_CANINTE, &wake_up_enabled);
        wake_up_enabled &= MCP_WAKIF;

        if(!wake_up_enabled) {
            modify_register(spi, MCP_CANINTE, MCP_WAKIF, MCP_WAKIF);
        }

        // Trigger wake by modifying CANINTF
        modify_register(spi, MCP_CANINTF, MCP_WAKIF, MCP_WAKIF);

        // Wait for mode to exit sleep
        uint32_t wake_timeout = furi_get_tick();
        while(get_mode(spi) == MCP_SLEEP && (furi_get_tick() - wake_timeout) < 50) {
            furi_delay_us(100);
        }

        if(!wake_up_enabled) {
            modify_register(spi, MCP_CANINTE, MCP_WAKIF, 0);
        }

        modify_register(spi, MCP_CANINTF, MCP_WAKIF, 0);
    }

    uint32_t time_out = furi_get_tick();

    time_out = furi_get_tick();

    do {
        if(!modify_register(spi, MCP_CANCTRL, CANCTRL_REQOP, MODE_CONFIG) ||
           !read_register(spi, MCP_CANSTAT, &read_status)) return false;

        read_status &= CANSTAT_OPM;
        if(read_status == MODE_CONFIG) ret = true;

        furi_delay_us(1);

    } while((ret != true) && ((furi_get_tick() - time_out) < 50));

    time_out = furi_get_tick();

    do {
        if(!modify_register(spi, MCP_CANCTRL, CANCTRL_REQOP, new_mode) ||
           !read_register(spi, MCP_CANSTAT, &read_status)) return false;

        read_status &= CANSTAT_OPM;
        if(read_status == new_mode) return true;

        furi_delay_us(1);

    } while((furi_get_tick() - time_out) < 50);

    return false;
}

// To set Config mode
bool set_config_mode(MCP2515* mcp_can) {
    bool ret = true;
    ret = set_new_mode(mcp_can, MODE_CONFIG);

    return ret;
}

// To set Normal Mode
bool set_normal_mode(MCP2515* mcp_can) {
    bool ret = true;
    ret = set_new_mode(mcp_can, MCP_NORMAL);
    return ret;
}

// To set ListenOnly Mode
bool set_listen_only_mode(MCP2515* mcp_can) {
    bool ret = true;
    ret = set_new_mode(mcp_can, MCP_LISTENONLY);
    return ret;
}

// To set Sleep Mode
bool set_sleep_mode(MCP2515* mcp_can) {
    bool ret = true;
    ret = set_new_mode(mcp_can, MCP_SLEEP);
    return ret;
}

// To set Loop Back Mode
bool set_loop_back_mode(MCP2515* mcp_can) {
    bool ret = true;
    ret = set_new_mode(mcp_can, MCP_LOOPBACK);
    return ret;
}

// To write the mask-filters for the chip
bool write_mf(FuriHalSpiBusHandle* spi, uint8_t address, uint8_t ext, uint32_t id) {
    uint16_t canId = (uint16_t)(id & 0x0FFFF);
    uint8_t bufData[4];

    if(ext) {
        bufData[MCP_EID0] = (uint8_t)(canId & 0xFF);
        bufData[MCP_EID8] = (uint8_t)(canId >> 8);
        canId = (uint16_t)(id >> 16);
        bufData[MCP_SIDL] = (uint8_t)(canId & 0x03);
        bufData[MCP_SIDL] += (uint8_t)((canId & 0x1C) << 3);
        bufData[MCP_SIDL] |= MCP_TXB_EXIDE_M;
        bufData[MCP_SIDH] = (uint8_t)(canId >> 5);
    } else {
        bufData[MCP_SIDL] = (uint8_t)((canId & 0x07) << 5);
        bufData[MCP_SIDH] = (uint8_t)(canId >> 3);
        bufData[MCP_EID0] = 0;
        bufData[MCP_EID8] = 0;
    }

    uint8_t instruction[] = {INSTRUCTION_WRITE, address};

    furi_hal_spi_acquire(spi);
    bool ok = furi_hal_spi_bus_tx(spi, instruction, sizeof(instruction), TIMEOUT_SPI) &&
              furi_hal_spi_bus_tx(spi, bufData, sizeof(bufData), TIMEOUT_SPI);
    furi_hal_spi_release(spi);
    return ok;
}

// Init can buffers
static bool init_can_buffer(FuriHalSpiBusHandle* spi) {
    const uint8_t address[] = {MCP_RXM0SIDH, MCP_RXM1SIDH, MCP_RXF0SIDH, MCP_RXF1SIDH,
        MCP_RXF2SIDH, MCP_RXF3SIDH, MCP_RXF4SIDH, MCP_RXF5SIDH};
    for(size_t i = 0; i < sizeof(address); i++) {
        if(!write_mf(spi, address[i], i < 3 || !(i & 1), 0)) return false;
    }
    for(uint8_t i = 0; i < 3; i++) {
        for(uint8_t offset = 0; offset < 14; offset++) {
            if(!set_register(spi, MCP_TXB0CTRL + i * 0x10 + offset, 0)) return false;
        }
    }
    return true;
}

// This function works to set Registers to initialize the MCP2515
static bool set_registers_init(FuriHalSpiBusHandle* spi) {
    return set_register(spi, MCP_CANINTE, MCP_RX0IF | MCP_RX1IF) &&
           set_register(spi, MCP_BFPCTRL, MCP_BxBFS_MASK | MCP_BxBFE_MASK) &&
           set_register(spi, MCP_TXRTSCTRL, 0) &&
           set_register(spi, MCP_RXB0CTRL, MCP_RXB_BUKT_MASK) &&
           set_register(spi, MCP_RXB1CTRL, 0);
}

// This function Works to set the Clock and Bitrate of the MCP2515
bool mcp_set_bitrate(FuriHalSpiBusHandle* spi, MCP_BITRATE bitrate, MCP_CLOCK clk) {
    uint8_t cfg1 = 0, cfg2 = 0, cfg3 = 0;

    switch(clk) {
    case MCP_8MHZ:
        switch(bitrate) {
        case MCP_125KBPS:
            cfg1 = MCP_8MHz_125kBPS_CFG1;
            cfg2 = MCP_8MHz_125kBPS_CFG2;
            cfg3 = MCP_8MHz_125kBPS_CFG3;
            break;
        case MCP_250KBPS:
            cfg1 = MCP_8MHz_250kBPS_CFG1;
            cfg2 = MCP_8MHz_250kBPS_CFG2;
            cfg3 = MCP_8MHz_250kBPS_CFG3;
            break;
        case MCP_500KBPS:
            cfg1 = MCP_8MHz_500kBPS_CFG1;
            cfg2 = MCP_8MHz_500kBPS_CFG2;
            cfg3 = MCP_8MHz_500kBPS_CFG3;
            break;
        case MCP_1000KBPS:
            cfg1 = MCP_8MHz_1000kBPS_CFG1;
            cfg2 = MCP_8MHz_1000kBPS_CFG2;
            cfg3 = MCP_8MHz_1000kBPS_CFG3;
            break;
        }
        break;
    case MCP_16MHZ:
        switch(bitrate) {
        case MCP_125KBPS:
            cfg1 = MCP_16MHz_125kBPS_CFG1;
            cfg2 = MCP_16MHz_125kBPS_CFG2;
            cfg3 = MCP_16MHz_125kBPS_CFG3;
            break;
        case MCP_250KBPS:
            cfg1 = MCP_16MHz_250kBPS_CFG1;
            cfg2 = MCP_16MHz_250kBPS_CFG2;
            cfg3 = MCP_16MHz_250kBPS_CFG3;
            break;
        case MCP_500KBPS:
            cfg1 = MCP_16MHz_500kBPS_CFG1;
            cfg2 = MCP_16MHz_500kBPS_CFG2;
            cfg3 = MCP_16MHz_500kBPS_CFG3;
            break;
        case MCP_1000KBPS:
            cfg1 = MCP_16MHz_1000kBPS_CFG1;
            cfg2 = MCP_16MHz_1000kBPS_CFG2;
            cfg3 = MCP_16MHz_1000kBPS_CFG3;
            break;
        }
        break;

    case MCP_20MHZ:
        switch(bitrate) {
        case MCP_125KBPS:
            cfg1 = MCP_20MHz_125kBPS_CFG1;
            cfg2 = MCP_20MHz_125kBPS_CFG2;
            cfg3 = MCP_20MHz_125kBPS_CFG3;
            break;
        case MCP_250KBPS:
            cfg1 = MCP_20MHz_250kBPS_CFG1;
            cfg2 = MCP_20MHz_250kBPS_CFG2;
            cfg3 = MCP_20MHz_250kBPS_CFG3;
            break;
        case MCP_500KBPS:
            cfg1 = MCP_20MHz_500kBPS_CFG1;
            cfg2 = MCP_20MHz_500kBPS_CFG2;
            cfg3 = MCP_20MHz_500kBPS_CFG3;
            break;
        case MCP_1000KBPS:
            cfg1 = MCP_20MHz_1000kBPS_CFG1;
            cfg2 = MCP_20MHz_1000kBPS_CFG2;
            cfg3 = MCP_20MHz_1000kBPS_CFG3;
            break;
        }
        break;
    }

    return set_register(spi, MCP_CNF1, cfg1) && set_register(spi, MCP_CNF2, cfg2) && set_register(spi, MCP_CNF3, cfg3);
}

// To set a Mask
void init_mask(MCP2515* mcp_can, uint8_t num_mask, uint32_t mask) {
    FuriHalSpiBusHandle* spi = mcp_can->spi;

    uint8_t ext = 0;

    set_config_mode(mcp_can);

    if(num_mask > 1) return;

    if(mask > 0x7FF) ext = 1;

    if(num_mask == 0) {
        write_mf(spi, MCP_RXM0SIDH, ext, mask);
    }

    if(num_mask == 1) {
        write_mf(spi, MCP_RXM1SIDH, ext, mask);
    }

    set_new_mode(mcp_can, mcp_can->mode);
}

// To set a Filter
void init_filter(MCP2515* mcp_can, uint8_t num_filter, uint32_t filter) {
    FuriHalSpiBusHandle* spi = mcp_can->spi;

    uint8_t ext = 0;

    set_config_mode(mcp_can);

    if(num_filter > 6) return;

    if(filter > 0x7FF) ext = 1;

    switch(num_filter) {
    case 0:
        write_mf(spi, MCP_RXF0SIDH, ext, filter);
        break;
    case 1:
        write_mf(spi, MCP_RXF1SIDH, ext, filter);
        break;

    case 2:
        write_mf(spi, MCP_RXF2SIDH, ext, filter);
        break;

    case 3:
        write_mf(spi, MCP_RXF3SIDH, ext, filter);
        break;

    case 4:
        write_mf(spi, MCP_RXF4SIDH, ext, filter);
        break;

    case 5:
        write_mf(spi, MCP_RXF5SIDH, ext, filter);
        break;

    default:
        break;
    }

    set_new_mode(mcp_can, mcp_can->mode);
}

// This function works to know if there is any message waiting
uint8_t read_rx_tx_status(FuriHalSpiBusHandle* spi) {
    uint8_t ret = 0;

    mcp_get_status(spi, &ret);

    ret &= (MCP_STAT_TXIF_MASK | MCP_STAT_RXIF_MASK);

    ret = (ret & MCP_STAT_TX0IF ? MCP_TX0IF : 0) | (ret & MCP_STAT_TX1IF ? MCP_TX1IF : 0) |
          (ret & MCP_STAT_TX2IF ? MCP_TX2IF : 0) | (ret & MCP_STAT_RXIF_MASK);

    return ret;
}

// The function to read the message
static bool read_frame(FuriHalSpiBusHandle* spi, CANFRAME* frame, uint8_t read_instruction) {
    uint8_t header[5] = {0};
    CANFRAME result = {0};
    furi_hal_spi_acquire(spi);
    bool ok = furi_hal_spi_bus_tx(spi, &read_instruction, 1, TIMEOUT_SPI) &&
              furi_hal_spi_bus_rx(spi, header, sizeof(header), TIMEOUT_SPI);
    if(ok) {
        result.ext = (header[MCP_SIDL] & MCP_TXB_EXIDE_M) != 0;
        result.canId = ((uint32_t)header[MCP_SIDH] << 3) | (header[MCP_SIDL] >> 5);
        if(result.ext) {
            result.canId = (result.canId << 18) | ((uint32_t)(header[MCP_SIDL] & 3) << 16) |
                           ((uint32_t)header[MCP_EID8] << 8) | header[MCP_EID0];
        }
        result.data_length = header[4] & MCP_DLC_MASK;
        if(result.data_length > MAX_LEN) result.data_length = MAX_LEN;
        // Standard RTR lives in RXBnSIDL.SRR, extended RTR in RXBnDLC.RTR.
        result.req = result.ext ? !!(header[4] & MCP_RTR_MASK) : !!(header[MCP_SIDL] & 0x10);
        if(result.data_length && !result.req) {
            ok = furi_hal_spi_bus_rx(spi, result.buffer, result.data_length, TIMEOUT_SPI);
        }
    }
    // READ RX BUFFER clears RXnIF at CS release. A second clear can discard
    // a new frame arriving between the two SPI transactions.
    furi_hal_spi_release(spi);
    if(ok) *frame = result;
    return ok;
}

// This function Works to get the Can message
ERROR_CAN read_can_message(MCP2515* mcp_can, CANFRAME* frame) {
    if(!mcp_can || !mcp_can->spi || !frame) return ERROR_SPI;
    uint8_t status = 0;
    if(!mcp_get_status(mcp_can->spi, &status)) return ERROR_SPI;
    uint8_t pending = status & (MCP_RX0IF | MCP_RX1IF);
    if(!pending) return ERROR_NOMSG;
    uint8_t selected = pending == 3 ? mcp_can->next_rx : (pending & MCP_RX0IF ? 0 : 1);
    mcp_can->next_rx = selected ^ 1;
    return read_frame(mcp_can->spi, frame, selected ? INSTRUCTION_READ_RX1 : INSTRUCTION_READ_RX0) ? ERROR_OK : ERROR_SPI;
}

// This function return the error in the can bus network
uint8_t get_error(MCP2515* mcp_can) {
    FuriHalSpiBusHandle* spi = mcp_can->spi;
    uint8_t err = 0;
    read_register(spi, MCP_EFLG, &err);
    modify_register(spi, MCP_EFLG, MCP_EFLG_RX0OVR, 0);
    modify_register(spi, MCP_EFLG, MCP_EFLG_RX1OVR, 0);
    return err;
}

// This function works to check if there is an error in the CANBUS network
ERROR_CAN check_error(MCP2515* mcp_can) {
    FuriHalSpiBusHandle* spi = mcp_can->spi;

    uint8_t eflg = 0;

    read_register(spi, MCP_EFLG, &eflg);

    if(eflg & MCP_EFLG_ERRORMASK) {
        return ERROR_FAIL;
    } else {
        return ERROR_OK;
    }
}

// This function works to get
ERROR_CAN check_receive(MCP2515* mcp_can) {
    uint8_t status = 0;
    if(!mcp_can || !mcp_can->spi || !mcp_get_status(mcp_can->spi, &status)) return ERROR_SPI;
    return status & (MCP_RX0IF | MCP_RX1IF) ? ERROR_OK : ERROR_NOMSG;
}

// TX completion is confirmed by TXnIF, independently of priority/arbitration bits.
static ERROR_CAN finish_or_abort_tx(FuriHalSpiBusHandle* spi, uint8_t ctrl, uint8_t flag, ERROR_CAN reason) {
    if(!modify_register(spi, ctrl, MCP_TXB_TXREQ_M, 0)) return ERROR_TX_UNCERTAIN;
    uint32_t start = furi_get_tick();
    do {
        uint8_t state = 0, interrupt = 0;
        if(!read_register(spi, ctrl, &state) || !read_register(spi, MCP_CANINTF, &interrupt)) return ERROR_TX_UNCERTAIN;
        if(!(state & MCP_TXB_TXREQ_M)) {
            if(interrupt & flag) return ERROR_OK; // Completed just before abort.
            return reason;
        }
        furi_delay_us(100);
    } while(furi_get_tick() - start < 5);
    return ERROR_TX_UNCERTAIN;
}

ERROR_CAN send_can_frame(MCP2515* mcp_can, CANFRAME* frame) {
    if(!mcp_can || !mcp_can->spi || !frame || frame->data_length > 8 ||
       frame->canId > 0x1FFFFFFF) return ERROR_FAILTX;
    FuriHalSpiBusHandle* spi = mcp_can->spi;
    uint8_t status = 0;
    if(!mcp_get_status(spi, &status)) return ERROR_SPI;
    uint8_t index = 0;
    while(index < 3 && (status & (MCP_STAT_TX0_PENDING << (index * 2)))) index++;
    if(index == 3) return ERROR_ALLTXBUSY; // Nothing submitted: safe to retry.
    uint8_t ctrl = MCP_TXB0CTRL + index * 0x10;
    uint8_t flag = MCP_TX0IF << index;
    uint8_t packet[15] = {INSTRUCTION_WRITE, ctrl + 1};
    uint32_t id = frame->canId;
    if(frame->ext || id > 0x7FF) {
        packet[2] = id >> 21;
        packet[3] = ((id >> 13) & 0xE0) | MCP_TXB_EXIDE_M | ((id >> 16) & 3);
        packet[4] = id >> 8;
        packet[5] = id;
    } else {
        packet[2] = id >> 3;
        packet[3] = (id & 7) << 5;
    }
    packet[6] = frame->data_length | (frame->req ? MCP_RTR_MASK : 0);
    if(!frame->req) memcpy(packet + 7, frame->buffer, frame->data_length);
    if(!modify_register(spi, MCP_CANINTF, flag, 0) ||
       !modify_register(spi, ctrl, MCP_TXB_ABTF_M | MCP_TXB_MLOA_M | MCP_TXB_TXERR_M, 0)) return ERROR_SPI;
    furi_hal_spi_acquire(spi);
    bool loaded = furi_hal_spi_bus_tx(spi, packet, 7 + (frame->req ? 0 : frame->data_length), TIMEOUT_SPI);
    furi_hal_spi_release(spi);
    if(!loaded) return ERROR_SPI;
    if(!modify_register(spi, ctrl, MCP_TXB_TXREQ_M, MCP_TXB_TXREQ_M)) {
        return finish_or_abort_tx(spi, ctrl, flag, ERROR_TX_UNCERTAIN);
    }
    uint32_t start = furi_get_tick();
    do {
        uint8_t state = 0, interrupt = 0, errors = 0;
        if(!read_register(spi, ctrl, &state) || !read_register(spi, MCP_CANINTF, &interrupt)) {
            return finish_or_abort_tx(spi, ctrl, flag, ERROR_TX_UNCERTAIN);
        }
        if(!(state & MCP_TXB_TXREQ_M)) {
            if(interrupt & flag) return ERROR_OK;
            return ERROR_FAILTX;
        }
        if(!read_register(spi, MCP_EFLG, &errors)) return finish_or_abort_tx(spi, ctrl, flag, ERROR_TX_UNCERTAIN);
        if(errors & MCP_EFLG_TXBO) return finish_or_abort_tx(spi, ctrl, flag, ERROR_BUSOFF);
        furi_delay_us(100);
    } while(furi_get_tick() - start < 10);
    return finish_or_abort_tx(spi, ctrl, flag, ERROR_SEND_MSG_TIMEOUT);
}

uint8_t read_detection_baudrate(FuriHalSpiBusHandle* spi) {
    uint8_t data_canintf = 0;

    uint8_t instruction[] = {INSTRUCTION_READ, MCP_CANINTF};
    furi_hal_spi_acquire(spi);
    furi_hal_spi_bus_tx(spi, instruction, sizeof(instruction), TIMEOUT_SPI);
    furi_hal_spi_bus_rx(spi, &data_canintf, 1, TIMEOUT_SPI);
    furi_hal_spi_release(spi);

    return (data_canintf & 0xf0);
}

// Function to detect the baudrate
ERROR_CAN is_this_bitrate(MCP2515* mcp_can, MCP_BITRATE bitrate) {
    FuriHalSpiBusHandle* spi = mcp_can->spi;
    ERROR_CAN ret = ERROR_OK;

    set_config_mode(mcp_can);

    mcp_set_bitrate(spi, bitrate, mcp_can->clck);

    set_listen_only_mode(mcp_can);

    if(check_receive(mcp_can) == ERROR_NOMSG) return ERROR_NOMSG;

    uint8_t data_canintf = 0;

    uint8_t instruction[] = {INSTRUCTION_READ, MCP_CANINTF};
    furi_hal_spi_acquire(spi);
    furi_hal_spi_bus_tx(spi, instruction, sizeof(instruction), TIMEOUT_SPI);
    furi_hal_spi_bus_rx(spi, &data_canintf, 1, TIMEOUT_SPI);
    furi_hal_spi_release(spi);

    data_canintf &= 0x80;

    if(data_canintf == 0x80) ret = ERROR_FAIL;

    set_register(spi, MCP_CANINTF, 0);

    return ret;
}

// This function works to alloc the struct
MCP2515* mcp_alloc(MCP_MODE mode, MCP_CLOCK clck, MCP_BITRATE bitrate) {
    MCP2515* mcp_can = calloc(1, sizeof(MCP2515));
    if(!mcp_can) return NULL;
    mcp_can->spi = spi_alloc();
    if(!mcp_can->spi) {
        free(mcp_can);
        return NULL;
    }
    mcp_can->mode = mode;
    mcp_can->bitRate = bitrate;
    mcp_can->clck = clck;
    return mcp_can;
}

// To deinit
void deinit_mcp2515(MCP2515* mcp_can) {
    if(!mcp_can || !mcp_can->spi) return;
    if(!mcp_can->spi_initialized) return;
    mcp_reset(mcp_can->spi);
    furi_hal_spi_bus_handle_deinit(mcp_can->spi);
    mcp_can->spi_initialized = false;
}

// free instance
void free_mcp2515(MCP2515* mcp_can) {
    if(!mcp_can) return;
    deinit_mcp2515(mcp_can);
    free(mcp_can->spi);
    free(mcp_can);
}

// This function starts the SPI communication and set the MCP2515 device
ERROR_CAN mcp2515_start(MCP2515* mcp_can) {
    if(!mcp_can || !mcp_can->spi) return ERROR_FAILINIT;
    if(mcp_can->spi_initialized) deinit_mcp2515(mcp_can);
    furi_hal_spi_bus_handle_init(mcp_can->spi);
    mcp_can->spi_initialized = true;
    mcp_can->next_rx = 0;

    bool ret = true;

    if(!mcp_reset(mcp_can->spi)) return ERROR_FAILINIT;

    furi_delay_ms(10);

    if(!set_new_mode(mcp_can, MODE_CONFIG) ||
       !mcp_set_bitrate(mcp_can->spi, mcp_can->bitRate, mcp_can->clck) ||
       !init_can_buffer(mcp_can->spi) || !set_registers_init(mcp_can->spi)) return ERROR_FAILINIT;

    ret = set_new_mode(mcp_can, mcp_can->mode);
    if(!ret) return ERROR_FAILINIT;

    return ERROR_OK;
}

// Init the mcp2515 device
ERROR_CAN mcp2515_init(MCP2515* mcp_can) {
    return mcp2515_start(mcp_can);
}
