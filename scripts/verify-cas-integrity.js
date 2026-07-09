const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// ตรวจสอบว่ามีไฟล์และมีรูปแบบ Header ที่ถูกต้อง
function verifyCASIntegrity() {
  console.log('🔍 เริ่มตรวจสอบความสมบูรณ์ของข้อมูล...');
  
  const targetDir = '.';
  const files = fs.readdirSync(targetDir, { withFileTypes: true });

  let allValid = true;

  for (const file of files) {
    if (file.isFile() && file.name.endsWith('.md') && file.name !== 'README.md') {
      const filePath = path.join(targetDir, file.name);
      const content = fs.readFileSync(filePath, 'utf8');
      
      // ตรวจสอบว่ามีบรรทัด HASH หรือไม่
      if (!content.includes('HASH:')) {
        console.log(`⚠️  ${file.name}: ไม่พบบรรทัด HASH`);
        continue;
      }

      // คำนวณ Hash ของเนื้อหา
      const calculatedHash = crypto.createHash('sha256').update(content).digest('hex');
      
      // ดึง Hash ที่ระบุในไฟล์
      const hashMatch = content.match(/HASH:\s*([a-f0-9]{64})/i);
      if (hashMatch) {
        const storedHash = hashMatch[1].toLowerCase();
        
        if (calculatedHash === storedHash) {
          console.log(`✅ ${file.name}: Hash ถูกต้อง`);
        } else {
          console.log(`❌ ${file.name}: Hash ไม่ตรงกัน`);
          console.log(`   ที่เก็บไว้: ${storedHash}`);
          console.log(`   คำนวณได้: ${calculatedHash}`);
          allValid = false;
        }
      } else {
        console.log(`⚠️  ${file.name}: รูปแบบ HASH ไม่ถูกต้อง`);
        allValid = false;
      }
    }
  }

  if (!allValid) {
    console.log('--------------------------------------------------');
    console.log('STATUS: REJECTED');
    console.log('REASON: INTEGRITY_CHECK_FAILED');
    console.log('NEXT: ตรวจสอบและอัปเดต Hash ในไฟล์');
    console.log('--------------------------------------------------');
    process.exit(1);
  } else {
    console.log('✅ ตรวจสอบความสมบูรณ์เสร็จสิ้น');
    process.exit(0);
  }
}

verifyCASIntegrity();

