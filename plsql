create sequence sequence1 start with 10 increment by 1;

-- Create table
create table AIS
(
  id          NUMBER(10) not null,
  name        CHAR(200),
  expiration  NUMBER,
  pass_length NUMBER(2)
)
tablespace USERS
  pctfree 10
  initrans 1
  maxtrans 255
  storage
  (
    initial 64K
    next 1M
    minextents 1
    maxextents unlimited
  );
-- Create/Recreate primary, unique and foreign key constraints 
alter table AIS
  add constraint ID_AIS primary key (ID)
  using index 
  tablespace USERS
  pctfree 10
  initrans 2
  maxtrans 255
  storage
  (
    initial 64K
    next 1M
    minextents 1
    maxextents unlimited
  );

-- Create table
create table USERS
(
  id          NUMBER(10) not null,
  iin         CHAR(12),
  first_name  CHAR(30),
  last_name   CHAR(30),
  middle_name CHAR(30),
  department  CHAR(200)
)
tablespace USERS
  pctfree 10
  initrans 1
  maxtrans 255
  storage
  (
    initial 64K
    next 1M
    minextents 1
    maxextents unlimited
  );
-- Create/Recreate primary, unique and foreign key constraints 
alter table USERS
  add constraint ID1 primary key (ID)
  using index 
  tablespace USERS
  pctfree 10
  initrans 2
  maxtrans 255
  storage
  (
    initial 64K
    next 1M
    minextents 1
    maxextents unlimited
  );

-- Create table
create table USER_ACCOUNTS
(
  id         NUMBER(10) not null,
  id_users   NUMBER(10),
  login      CHAR(20),
  password   CHAR(200),
  begin_date DATE,
  isblocked  CHAR(1),
  id_ais     NUMBER(10)
)
tablespace USERS
  pctfree 10
  initrans 1
  maxtrans 255;
-- Create/Recreate primary, unique and foreign key constraints 
alter table USER_ACCOUNTS
  add constraint ID2 primary key (ID)
  using index 
  tablespace USERS
  pctfree 10
  initrans 2
  maxtrans 255;
alter table USER_ACCOUNTS
  add constraint ID_USERS foreign key (ID_USERS)
  references USERS (ID);

create or replace noneditionable procedure proc_ais  (p_name in varchar2,
                                       p_expiration in integer, 
                                       p_pass_length in integer,
                                       smessage    out varchar2,
                                       nResult     out integer) is
                                     

cnt integer;  
s_name varchar2(500);
begin  

  nResult:=0;
  if p_name is null then 
    smessage:='Name System is empty';
    nResult:=-1;
    return;
  end if;
  s_name:=rtrim(ltrim(upper(p_name)));
  select count(*) into cnt from ais a where upper(a.name)=s_name;
  if cnt=0 then 
    -- new system
    insert into ais (id, name, expiration, pass_length)
                values (sequence1.nextval, p_name, p_expiration, p_pass_length);
    commit;
  else
    -- update system table
    update ais 
           set name=p_name, expiration=p_expiration, pass_length=p_pass_length
           where upper(name)=s_name;
    commit;
  end if;
end;

create or replace noneditionable procedure proc_users(p_IIN in varchar2,
                                       p_first_name  in varchar2, 
                                       p_Last_name   in varchar2, 
                                       p_middle_name in varchar2, 
                                       p_department  in varchar2,
                                       smessage    out varchar2,
                                       nResult     out integer) is
                                     

cnt integer;  
begin  

  nResult:=0;
  if p_iin is null then 
    smessage:='Value IIN is empty';
    nResult:=-1;
    return;
  end if;

  select count(*) into cnt from users u where u.iin=p_iin;
  if cnt=0 then 
    -- new user
    insert into users (id,iin,first_name,last_name,middle_name,department)
                values (sequence1.nextval, p_iin, p_first_name, p_last_name, p_middle_name, p_department);
    commit;
  else
    -- update users
    update users 
           set first_name=p_first_name, last_name=p_last_name, middle_name=p_middle_name,department=p_department
           where iin=p_iin;
    commit;
  end if;
end;

CREATE OR REPLACE NONEDITIONABLE FUNCTION CryptSTR (spass IN VARCHAR2)
   RETURN VARCHAR2
IS

   spass_crypt   RAW (4000);
   l_mod      NUMBER  :=   DBMS_CRYPTO.encrypt_aes128 + DBMS_CRYPTO.chain_cbc + DBMS_CRYPTO.pad_pkcs5;
BEGIN
   spass_crypt := DBMS_CRYPTO.encrypt (utl_i18n.string_to_raw (spass, 'AL32UTF8'),
                               l_mod,
                               utl_i18n.string_to_raw ('1234567890123456', 'AL32UTF8')
                              );

   RETURN spass_crypt;
END;

CREATE OR REPLACE NONEDITIONABLE FUNCTION DeCryptSTR (spass_crypt IN raw)
   RETURN VARCHAR2
IS
   spass_decrypt   RAW (4000);
   l_key      VARCHAR2 (2000) := '1234567890123456';
   l_in_val   RAW (2000)      := HEXTORAW (spass_crypt);
   l_mod      NUMBER  :=   DBMS_CRYPTO.encrypt_aes128 + DBMS_CRYPTO.chain_cbc + DBMS_CRYPTO.pad_pkcs5;

BEGIN

          spass_decrypt :=
          DBMS_CRYPTO.decrypt(l_in_val,
                              l_mod,
                              utl_i18n.string_to_raw (l_key, 'AL32UTF8')
                              );
          RETURN spass_decrypt;      
          
END;

create or replace noneditionable procedure Proc_User_Accounts (
                                       p_IIN in varchar2,
                                       p_system in varchar2, 
                                       p_Login in varchar2, 
                                       p_pass in varchar2, 
                                       p_department in varchar2,
                                       smessage out varchar2,
                                       nResult out integer) is
                                     

cnt integer;  
sTemp varchar2(200);
nSys integer;
nUser integer;
sPass varchar2(200);
nExp integer;
nlen integer;
begin  

  nResult:=0;
  
  if p_iin is null then 
    smessage:='Value IIN is empty';
    nResult:=-1;
    return;
  end if;

  if p_system is null then 
    smessage:='Value SYSTEM is empty';
    nResult:=-1;
    return;
  end if;
  
  if p_Login is null then 
    smessage:='User LOGIN is empty';
    nResult:=-1;
    return;
  end if;

  if p_pass is null then 
    smessage:='User PASSWORD is empty';
    nResult:=-1;
    return;
  end if;  

  select count(*) into cnt from users u where u.iin=p_iin;
    if cnt=0 then 
      smessage:='User with IIN = '||p_iin||' not found';
      nResult:=-1;
      return;
    else
      select id into nUser from users u where u.iin=p_iin;
    end if;

  select count(*) into cnt from ais a where upper(a.name)=stemp;
    if cnt=0 then 
      smessage:='System with name = '||p_system||' not found';
      nResult:=-1;
      return;
    else
      stemp:=rtrim(ltrim(upper(p_system)));
      select id, a.expiration, a.pass_length  into nSys, nExp, nlen  from ais a where upper(a.name)=stemp; 
    end if;

  -- �������� Password. Check length
  sPass:=decryptstr(p_pass); 
  if length(sPass)<nlen then
      smessage:='Password length is less then requirment';
      nResult:=-1;
      return;    
  end if;
  
  -- �� ���� ��������� Login, id system, id user ���������� ����� � ������� USER_ACCOUNTS. 
  -- ���� ����� ������ �� �������, �� ��������� ����� ������ � �������.
  
  select count(*) into cnt
  from USER_ACCOUNTS ua
  where ua.login=p_Login and ua.id_users=nUser and ua.id_ais=nsys;
  
  
  if cnt=0 then 
    -- new row in USER_ACCOUNTS
    insert into USER_ACCOUNTS (ID,ID_USERS,ID_AIS,LOGIN,PASSWORD,BEGIN_DATE,ISBLOCKED)
                values (sequence1.nextval,nUser,nSys,p_Login,p_pass,sysdate,0);
    commit;
    return;
  end if;
  
  
end;
