import React from 'react';
import BrowserOnly from '@docusaurus/BrowserOnly';
import useBaseUrl from '@docusaurus/useBaseUrl';

export default function AsciinemaPlayer({
  src,
  rows = 24,
  cols = 80,
  idleTimeLimit = 2,
  autoPlay = false,
  poster = 'npt:0:3',
  speed = 1,
}) {
  const resolvedSrc = useBaseUrl(src);
  return (
    <BrowserOnly fallback={<div>Loading player...</div>}>
      {() => {
        const AsciinemaPlayerLib = require('asciinema-player');
        require('asciinema-player/dist/bundle/asciinema-player.css');

        const ref = React.useRef(null);
        const playerRef = React.useRef(null);

        React.useEffect(() => {
          if (ref.current && !playerRef.current) {
            playerRef.current = AsciinemaPlayerLib.create(resolvedSrc, ref.current, {
              rows,
              cols,
              idleTimeLimit,
              autoPlay,
              poster,
              speed,
            });
          }

          return () => {
            if (playerRef.current) {
              playerRef.current.dispose();
              playerRef.current = null;
            }
          };
        }, [resolvedSrc]);

        return <div ref={ref} />;
      }}
    </BrowserOnly>
  );
}
