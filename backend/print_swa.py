import io
text = io.open('dump3.txt', encoding='utf-16le').read()
lines = text.split('\n')
try:
    start = lines.index('DEVICE: SW-A')
except ValueError:
    start = lines.index('DEVICE: SW-A\r') if 'DEVICE: SW-A\r' in lines else -1

if start != -1:
    end = start
    while end < len(lines) and 'end' not in lines[end]:
        end += 1
    
    print('\n'.join(lines[start:start+100]))
