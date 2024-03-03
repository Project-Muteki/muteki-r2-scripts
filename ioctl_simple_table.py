import r2pipe

def main():
    r = r2pipe.open()
    r.cmd('s loc.ioctl_simple_table')

    while True:
        dev, desc = r.cmdj('pv4j 2')
        if dev['value'] == 0 and desc['value'] == 0:
            break
        callback = r.cmdj(f'pv4j @ {desc["value"]} + 0x24')[0]
        if callback['value'] != 0:
            print(f'f fcn.ioctl_simple_callback_dev_{dev["value"]:#x} @ {callback["value"]:#x}')
        r.cmd('s +8')


if __name__ == '__main__':
    main()
