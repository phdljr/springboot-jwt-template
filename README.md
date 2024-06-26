# springboot-jwt-template

# 개요
- JWT를 통해 인증/인가를 구현하는데 참고가 되는 템플릿 생성

# 구성
- AccessToken과 RefreshToken 구현
  - reissue api: `/reissue`
- RefreshToken Rotate 구현
  - AccessToken을 재발급받을 때, RefreshToken도 재발급받는 형식
- RefreshToken DB 구현
  - DB에 존재하는 RefreshToken만 유효한 토큰으로 판단
  - MySQL로 구현 -> Redis로 교체하면 더 좋을 듯
    - 접근성, 속도, TTL을 통한 관리 등의 이점이 존재
- Logout 구현
  - RefreshToken DB에서 제거하는 로직 존재

# 참고
- Controller에 비즈니스 로직을 작성해둠
  - 이를 서비스단으로 분리시킬 필요가 있음
- Logout 필터를 다른 방식으로 구현할 필요성이 있다고 판단

# 참조
- JWT
  - https://www.youtube.com/watch?v=NPRh2v7PTZg&list=PLJkjrxxiBSFCcOjy0AAVGNtIa08VLk1EJ
- RefreshToken
  - https://www.youtube.com/watch?v=SxfweG-F6JM&list=PLJkjrxxiBSFATow4HY2qr5wLvXM6Rg-BM
