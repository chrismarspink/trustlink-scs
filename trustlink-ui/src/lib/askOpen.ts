// 다른 화면에서 묻고 찾기를 열어 바로 묻게 한다: askOpen('CVE-… VEX 판정 초안')
export const askOpen = (q: string) => window.dispatchEvent(new CustomEvent('tl-ask', { detail: { q } }));
