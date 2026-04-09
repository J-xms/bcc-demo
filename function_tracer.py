#!/usr/bin/env python3
import json
import sys
import time
import os
import argparse
import platform
from datetime import datetime
from bcc import BPF

ARCH = platform.machine()
if ARCH == 'aarch64':
    PARM_MACRO = 'PT_REGS_ARM64_PARM'
else:
    PARM_MACRO = 'PT_REGS_PARM'

HEADER = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct data_t {
    u64 ts;
    u64 latency;
    u64 pid;
    u32 tid;
    u64 func_id;
    u64 kern_stack_id;
    u64 user_stack_id;
    u64 arg0;
    u64 arg1;
    u64 arg2;
    u64 arg3;
    u64 arg4;
    u64 arg5;
};

struct arg_t {
    u64 arg0;
    u64 arg1;
    u64 arg2;
    u64 arg3;
    u64 arg4;
    u64 arg5;
};

struct meta_t {
    u64 last_ts;
    u32 counter;
};

BPF_HASH(start, u32);
BPF_HASH(args, u32, struct arg_t);
BPF_PERF_OUTPUT(events);
BPF_HASH(counter_map, u32, u32);
BPF_HASH(meta_map, u32, struct meta_t);
BPF_STACK_TRACE(kern_stacks, 1024);
BPF_STACK_TRACE(user_stacks, 1024);
"""

FUNC_ENTRY = """
int entry_%(name)s(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    %(sample_check)s
    u64 ts = bpf_ktime_get_ns();
    start.update(&pid, &ts);
    
    struct arg_t a = {
        .arg0 = PARM1(ctx),
        .arg1 = PARM2(ctx),
        .arg2 = PARM3(ctx),
        .arg3 = PARM4(ctx),
        .arg4 = PARM5(ctx),
        .arg5 = PARM6(ctx)
    };
    args.update(&pid, &a);
    return 0;
}
"""

FUNC_EXIT = """
int exit_%(name)s(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = pid_tgid & 0xffffffff;
    u64 *tsp = start.lookup(&pid);
    struct arg_t *ap = args.lookup(&pid);
    if (tsp == 0 || ap == 0)
        return 0;

    u64 ts = bpf_ktime_get_ns();
    s64 kern_stack_id = kern_stacks.get_stackid(ctx, 0);
    s64 user_stack_id = user_stacks.get_stackid(ctx, 0x100 | 0x200);
    
    struct data_t data = {
        .ts = ts,
        .latency = ts - *tsp,
        .pid = pid,
        .tid = tid,
        .func_id = %(func_id)d,
        .kern_stack_id = kern_stack_id,
        .user_stack_id = user_stack_id,
        .arg0 = ap->arg0,
        .arg1 = ap->arg1,
        .arg2 = ap->arg2,
        .arg3 = ap->arg3,
        .arg4 = ap->arg4,
        .arg5 = ap->arg5
    };

    events.perf_submit(ctx, &data, sizeof(data));
    
    u32 fkey = %(func_id)d;
    struct meta_t *meta = meta_map.lookup(&fkey);
    if (meta) {
        meta->last_ts = ts;
        __sync_fetch_and_add((int *)&meta->counter, 1);
    }
    
    start.delete(&pid);
    args.delete(&pid);
    return 0;
}
"""


class FunctionTracer:
    def __init__(self, config_path, output_dir='./results'):
        with open(config_path, 'r') as f:
            self.config = json.load(f)
        self.output_dir = output_dir
        self.results = []
        self.bpf = None
        self.func_map = {}

    def _handle_event(self, cpu, data, size):
        event = self.bpf['events'].event(data)
        func_name = self.func_map.get(event.func_id, "unknown")
        
        arg_values = [event.arg0, event.arg1, event.arg2, event.arg3, event.arg4, event.arg5]
        target = next((t for t in self.config['targets'] if t['name'] == func_name), None)
        arg_count = len(target.get('arg_types', [])) if target else 6
        
        kern_stack_id = event.kern_stack_id
        user_stack_id = event.user_stack_id
        kern_stack = []
        user_stack = []
        
        if kern_stack_id >= 0:
            try:
                for addr in self.bpf['kern_stacks'].walk(kern_stack_id):
                    sym = self.bpf.ksym(addr)
                    if b'[unknown]' in sym:
                        kern_stack.append(hex(addr))
                    else:
                        kern_stack.append(sym.decode('utf-8', 'replace') if isinstance(sym, bytes) else str(sym))
            except:
                pass
        
        if user_stack_id >= 0:
            try:
                for addr in self.bpf['user_stacks'].walk(user_stack_id):
                    sym = self.bpf.sym(addr, event.pid)
                    if b'[unknown]' in sym:
                        user_stack.append(hex(addr))
                    else:
                        user_stack.append(sym.decode('utf-8', 'replace') if isinstance(sym, bytes) else str(sym))
            except:
                pass
        
        entry = {
            'timestamp': int(event.ts / 1000),
            'latency_us': round(event.latency / 1000, 3),
            'pid': event.pid,
            'tid': event.tid,
            'func': func_name,
            'args': [hex(arg_values[i]) for i in range(min(arg_count, 6))],
            'kern_stack': kern_stack,
            'kern_stack_id': kern_stack_id,
            'user_stack': user_stack,
            'user_stack_id': user_stack_id
        }
        self.results.append(entry)

    def start(self, duration, freq=1):
        if freq == 1:
            sample_check = ""
        else:
            min_interval_ns = 1_000_000_000
            sample_check = """
    u32 fkey = FUNC_ID;
    u32 *cnt = counter_map.lookup(&fkey);
    if (cnt == 0) return 0;
    __sync_fetch_and_add((int *)cnt, 1);
    if (*cnt % FREQ != 0) {
        struct meta_t *meta = meta_map.lookup(&fkey);
        if (meta == 0) return 0;
        u64 now = bpf_ktime_get_ns();
        if (now - meta->last_ts < MIN_INTERVAL_NS) return 0;
    }
""".replace("FREQ", str(freq)).replace("MIN_INTERVAL_NS", str(min_interval_ns))
        
        all_code = HEADER

        for idx, target in enumerate(self.config['targets']):
            name = target['name']
            target_type = target.get('type', 'kernel')
            self.func_map[idx + 1] = name
            sc = sample_check.replace("FUNC_ID", str(idx + 1))
            all_code += FUNC_ENTRY % {'name': name, 'sample_check': sc}
            all_code += FUNC_EXIT % {'name': name, 'func_id': idx + 1}
        
        parm_macro = PARM_MACRO
        all_code = all_code.replace('PARM1', f'{parm_macro}1')
        all_code = all_code.replace('PARM2', f'{parm_macro}2')
        all_code = all_code.replace('PARM3', f'{parm_macro}3')
        all_code = all_code.replace('PARM4', f'{parm_macro}4')
        all_code = all_code.replace('PARM5', f'{parm_macro}5')
        all_code = all_code.replace('PARM6', f'{parm_macro}6')

        self.bpf = BPF(text=all_code)
        
        counter_table = self.bpf['counter_map']
        meta_table = self.bpf['meta_map']
        for idx, target in enumerate(self.config['targets']):
            fkey = idx + 1
            key = counter_table.Key(fkey)
            counter_table[key] = counter_table.Leaf(0)
            meta_table[key] = meta_table.Leaf()
        
        for idx, target in enumerate(self.config['targets']):
            name = target['name']
            target_type = target.get('type', 'kernel')
            
            if target_type == 'kernel':
                self.bpf.attach_kprobe(event=name, fn_name=f'entry_{name}')
                self.bpf.attach_kretprobe(event=name, fn_name=f'exit_{name}')
            elif target_type == 'usdt':
                lib = target.get('lib', '')
                if lib:
                    self.bpf.attach_uprobe(name=lib, sym=name, fn_name=f'entry_{name}')
                    self.bpf.attach_uretprobe(name=lib, sym=name, fn_name=f'exit_{name}')
            elif target_type == 'tracepoint':
                category, event = name.split(':')
                self.bpf.attach_tracepoint(tp=f'{category}:{event}', fn_name=f'entry_{name}')

        self.bpf['events'].open_perf_buffer(self._handle_event)

        print(f"Tracing for {duration} seconds... Press Ctrl+C to stop early.")
        start_time = time.time()

        try:
            while time.time() - start_time < duration:
                self.bpf.perf_buffer_poll(timeout=1000)
        except KeyboardInterrupt:
            print("\nInterrupted by user.")

        self._save_results()

    def _save_results(self):
        os.makedirs(self.output_dir, exist_ok=True)
        output_file = os.path.join(self.output_dir, f"trace_{int(time.time())}.json")

        with open(output_file, 'w') as f:
            json.dump({
                'results': self.results,
                'total_events': len(self.results)
            }, f, indent=2)
        print(f"Results saved to {output_file}, total events: {len(self.results)}")


def main():
    parser = argparse.ArgumentParser(description='BPF Function Tracer')
    parser.add_argument('-r', '--rules', required=True, help='Path to JSON rules file')
    parser.add_argument('-t', '--time', type=int, default=10, help='Tracing duration in seconds (default: 10)')
    parser.add_argument('-f', '--freq', type=int, default=1, help='Sampling frequency (1=100%%, 10=10%%, 100=1%%, default: 1)')

    args = parser.parse_args()

    if not os.path.exists(args.rules):
        print(f"Error: Rules file not found: {args.rules}")
        sys.exit(1)

    tracer = FunctionTracer(args.rules)
    tracer.start(args.time, args.freq)


if __name__ == '__main__':
    main()
