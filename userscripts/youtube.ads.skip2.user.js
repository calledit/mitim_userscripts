// ==UserScript==
// @name           YAAS (YouTube Ads Auto Skip)
// @description    Automatically closes the banner ad or clicks the "Skip ad" button.
// @name:uk        YAAS (Автоматичний пропуск реклами на YouTube).
// @description:uk Автоматично закриває рекламний банер чи клікає по кнопці "Пропустити рекламу".
// @version        3.0.3
// @namespace      https://greasyfork.org/uk/users/741855
// @author         boboha
// @match          *://*.youtube.com/*
// ==/UserScript==

(function() {
    'use strict';

    let skiped = true,
        player,
        video;
    const SEC = 1000,
          TO = 0 * SEC,
          TO_SUBSCIBED_VIDEO = 15 * SEC,
          TO_SUBSCIBED_BANNER = 5 * SEC,
          SPEED = 4,
          log = (...msg) => { console.log('[YAAS]', ...msg) },
          isSubscribed = () => document.querySelector('#subscribe-button [subscribed]') ? true : false,
          skipVideo = (btn) => {
              skiped = false;
              btn.addEventListener('click', setSkiped, false);
              setTimeout(() => {
                  skip(btn);
              }, isSubscribed() ? TO_SUBSCIBED_VIDEO : TO);
          },
          setSkiped = () => { skiped = true; log('Video skiped!') },
          skip = (btn) => {
              if (btn.nodeType === 1 && getComputedStyle(btn).display === 'inline-block') {
                  btn.click();
              } else {
                  setTimeout(() => {
                      !skiped && skip(btn);
                  }, 100);
              }
          },
          closeBanner = (btn) => {
              btn.addEventListener('click', setClosed, false);
              setTimeout(() => {
                  btn.click();
              }, isSubscribed() ? TO_SUBSCIBED_BANNER : TO);
          },
          setClosed = () => { log('Banner closed!') },
          observer = new MutationObserver(mutations => {
                  for (const mutation of mutations) {
                      try {
                          if (mutation.target.className === 'video-ads ytp-ad-module') {
                              if (mutation.addedNodes.length) {
                                  // Video loading
                                  if (mutation.addedNodes[0].className === 'ytp-ad-player-overlay') {
                                      video.muted=true;
                                      video.playbackRate = SPEED;
                                      log('Video is loaded...', '(', Math.round(video.duration), 's )');
                                  }
                                  // Banner loading
                                  else if (mutation.addedNodes[0].className === 'ytp-ad-overlay-slot') {
                                      log('Banner is loaded...');
                                      // Banner closing
                                      const close_button = mutation.addedNodes[0].querySelector('.ytp-ad-overlay-close-container > .ytp-ad-overlay-close-button');
                                      close_button && closeBanner(close_button);
                                  }
                              } else if (mutation.removedNodes.length) {
                                  if (mutation.removedNodes[0].id.startsWith('player-overlay')) {
                                      video.muted=false;
                                      log('Video ended');
                                  }
                              }
                          }

                          // Video skiping
                          if (mutation.target.className === 'ytp-ad-skip-button-slot') {
                              const skip_button = mutation.target.querySelector('.ytp-ad-skip-button-container > .ytp-ad-skip-button');
                              skip_button && skipVideo(skip_button);
                          }
                      } catch (e) {
                          console.groupCollapsed(e.message, mutation.target);
                          log(mutation);
                          console.groupEnd();
                      }
                  }
          }),
          initPlayer = () => {
              if (player) {
                  log('Init Player');
              } else {
                  player = document.querySelector('#movie_player');
                  setTimeout(initPlayer, 10);
              }
          },
          toggleObserver = () => {
              if (location.pathname === '/watch') {
                  if (player) {
                      if (!video) {
                          video = document.querySelector('video.html5-main-video');
                          observer.observe(player, {childList: true, attributes: true, subtree: true});
                          log('Observer start');
                      }
                  } else {
                      initPlayer();
                      setTimeout(toggleObserver, 10);
                  }
              } else {
                  if (player) {
                      observer.disconnect();
                      player = null;
                      video = null;
                      log('Observer stop');
                  } else {
                    initPlayer();  
                  }
              }
          };

    window.addEventListener('yt-navigate-start', toggleObserver);
    toggleObserver();

})();// ==UserScript==
// @name               No more youtube ads! - UPDATED
// @name:zh-CN         隐藏youtube google广告
// @namespace          Grenade Vault
// @version            1.1.7
// @description        Automatically Skips all youtube ads! with no waiting time.
// @description        Stop Stealing my code yes please
// @description:zh-CN  BF5 : This skips all adds instantly. Youtube.com
// @author             高梨フブキ
// @match              *://www.youtube.com/*
// ==/UserScript==

(function() {
    'use strict';
    var closeAd=function (){
        var css = '.video-ads .ad-container .adDisplay,#player-ads,.ytp-ad-module,.ytp-ad-image-overlay{ display: none!important; }',
            head = document.head || document.getElementsByTagName('head')[0],
            style = document.createElement('style');

        style.type = 'text/css';
        if (style.styleSheet){
            style.styleSheet.cssText = css;
        } else {
            style.appendChild(document.createTextNode(css));
        }

        head.appendChild(style);
    };
    var skipInt;
    var log=function(msg){
       // unsafeWindow.console.log (msg);
    };
    var skipAd=function(){
        //ytp-ad-preview-text
        //ytp-ad-skip-button
        var skipbtn=document.querySelector(".ytp-ad-skip-button.ytp-button")||document.querySelector(".videoAdUiSkipButton ");
        //var skipbtn=document.querySelector(".ytp-ad-skip-button ")||document.querySelector(".videoAdUiSkipButton ");
        if(skipbtn){
           skipbtn=document.querySelector(".ytp-ad-skip-button.ytp-button")||document.querySelector(".videoAdUiSkipButton ");
           log("skip");
           skipbtn.click();
           if(skipInt) {clearTimeout(skipInt);}
           skipInt=setTimeout(skipAd,488);
         }else{
              log("checking...");
              if(skipInt) {clearTimeout(skipInt);}
              skipInt=setTimeout(skipAd,488);
         }
    };

    closeAd();
    skipAd();

})();