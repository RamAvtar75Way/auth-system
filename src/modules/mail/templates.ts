export function otpEmailTemplate(code: string): string {
  return `
    <div style="font-family: sans-serif">
      <h2>Email Verification Code</h2>
      <p>Your verification code is:</p>
      <h1>${code}</h1>
      <p>This code expires in 10 minutes.</p>
    </div>
  `;
}
