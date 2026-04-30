import math
import subprocess

TOPK_VALUES = list(range(1, 22, 2))

BASE_CMD = [
    'python', 'main.py', 'Linux',
    '--device', 'cpu',
    '--download_datasets', 'False',
    '--preprocessing', 'False',
    '--train_samples', '500',
    '--init_num_epochs', '5',
    '--logGPT_episode', '5',
    '--window_size', '60',
    '--step_size', '30',

]

for top_k in TOPK_VALUES:
    cmd = BASE_CMD + ['--top_k', str(top_k)]
    print('='*80)
    print(f'Running top_k={top_k}')
    print(' '.join(cmd))
    print('='*80)
    subprocess.run(cmd, check=False)
