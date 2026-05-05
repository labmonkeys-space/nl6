import React, {useEffect, useState} from 'react';
import {TERMINAL_SCRIPT, type TerminalLine} from './data';

function useTypewriter(lines: TerminalLine[], speed = 12, lineDelay = 140) {
  const [idx, setIdx] = useState(0);
  const [chars, setChars] = useState(0);

  useEffect(() => {
    if (idx >= lines.length) {
      return; // play-once: freeze on the final line
    }
    const line = lines[idx];
    if (line.k === 'blank') {
      const t = setTimeout(() => { setIdx(i => i + 1); setChars(0); }, lineDelay);
      return () => clearTimeout(t);
    }
    if (line.k === 'bar') {
      let p = 0;
      const id = setInterval(() => {
        p += 4;
        setChars(Math.min(p, 100));
        if (p >= 100) {
          clearInterval(id);
          setTimeout(() => { setIdx(i => i + 1); setChars(0); }, 220);
        }
      }, 24);
      return () => clearInterval(id);
    }
    if (chars < line.text.length) {
      const t = setTimeout(() => setChars(c => c + 1), line.k === 'cmd' ? speed + 18 : speed);
      return () => clearTimeout(t);
    }
    const t = setTimeout(() => { setIdx(i => i + 1); setChars(0); }, lineDelay);
    return () => clearTimeout(t);
  }, [idx, chars, lines, speed, lineDelay]);

  return {idx, chars};
}

export default function Terminal(): JSX.Element {
  const {idx, chars} = useTypewriter(TERMINAL_SCRIPT);
  const out: React.ReactNode[] = [];

  for (let i = 0; i <= idx && i < TERMINAL_SCRIPT.length; i++) {
    const line = TERMINAL_SCRIPT[i];
    const isCurrent = i === idx;

    if (line.k === 'bar') {
      const pct = isCurrent ? chars : 100;
      const done = Math.round(pct / 2.5);
      const cells = Array.from({length: 40}, (_, k) => (k < done ? '█' : '░')).join('');
      out.push(
        <div key={i} className="nl6-tl nl6-tl--bar">
          <span className="nl6-tl__pfx">»</span>
          <span className="nl6-tl__bar">[{cells}] {String(pct).padStart(3, ' ')}%</span>
        </div>,
      );
    } else if (line.k === 'cmd') {
      out.push(
        <div key={i} className="nl6-tl nl6-tl--cmd">
          <span className="nl6-tl__pfx nl6-tl__pfx--prompt">noc@laptop</span>
          <span className="nl6-tl__colon">:</span>
          <span className="nl6-tl__path">~</span>
          <span className="nl6-tl__colon">$</span>
          <span className="nl6-tl__txt">&nbsp;{isCurrent ? line.text.slice(0, chars) : line.text}</span>
          {isCurrent && <span className="nl6-tl__caret" />}
        </div>,
      );
    } else if (line.k === 'blank') {
      out.push(<div key={i} className="nl6-tl nl6-tl--blank">&nbsp;</div>);
    } else if (line.k === 'ok') {
      out.push(
        <div key={i} className="nl6-tl nl6-tl--ok">
          <span className="nl6-tl__pfx">✓</span>
          <span className="nl6-tl__txt">{isCurrent ? line.text.slice(0, chars) : line.text}</span>
          {isCurrent && <span className="nl6-tl__caret" />}
        </div>,
      );
    } else {
      out.push(
        <div key={i} className="nl6-tl">
          <span className="nl6-tl__pfx">·</span>
          <span className="nl6-tl__txt">{isCurrent ? line.text.slice(0, chars) : line.text}</span>
          {isCurrent && <span className="nl6-tl__caret" />}
        </div>,
      );
    }
  }

  return (
    <div className="nl6-term">
      <div className="nl6-term__hd">
        <span className="nl6-term__dots"><i /><i /><i /></span>
        <span className="nl6-term__title">noc@laptop — ~ — 132×36</span>
      </div>
      <div className="nl6-term__body">{out}</div>
    </div>
  );
}
