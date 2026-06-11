import io
text = io.open('dump3.txt', encoding='utf-16le').read()
lines = text.split('\n')
try:
    start = lines.index('DEVICE: MLS-D')
except ValueError:
    start = lines.index('DEVICE: MLS-D\r') if 'DEVICE: MLS-D\r' in lines else -1

if start != -1:
    end = start
    while end < len(lines) and 'end' not in lines[end]:
        end += 1
    
    mls_config = lines[start:end+1]
    for i, line in enumerate(mls_config):
        if 'GigabitEthernet1/0/1' in line or 'GigabitEthernet1/0/2' in line or 'GigabitEthernet1/0/3' in line or 'GigabitEthernet1/0/4' in line:
            print('\n'.join(mls_config[i:i+6]))
            print('-'*40)
